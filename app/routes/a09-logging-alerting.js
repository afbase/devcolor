'use strict';
/**
 * A09:2025 — Security Logging & Alerting Failures  (#9)
 *
 * Renamed for 2025: "Monitoring" became "ALERTING". Collecting logs is not the
 * point — NOTICING is. This category is about attacks you can't see, can't
 * investigate, and are never alerted to.
 *
 * The failures taught here:
 *   1. Auditable events (login failures) that are never recorded → an attacker
 *      can brute-force forever and leave no trace.
 *   2. LOG INJECTION — writing untrusted text straight into a line-oriented log
 *      lets an attacker forge log lines with an embedded newline.
 *   3. Logging SECRETS — dumping raw request bodies leaks passwords/cards into
 *      the one place everyone has read access to.
 *   4. No alerting — even when the data is there, nothing trips.
 *
 * >>> This lab drives the Grafana demo. The SAFE side feeds two Prometheus
 *     counters (lab_auth_attempts_total, lab_security_alerts_total); the VULN
 *     side touches neither, so the same attack is invisible on the dashboard.
 */
const express = require('express');
const { metrics } = require('../metrics');

// Separate buffers on purpose: the vuln and safe sides must not share state, or
// the "vuln logged nothing" proof would be contaminated by the safe side.
const vulnLog = [];
const safeLog = [];

// Per-username failure tally for brute-force detection (safe side only).
const failuresByUser = new Map();
const safeAlerts = [];
const BRUTE_FORCE_THRESHOLD = 5;

// The single hardcoded credential both logins check, so the labs line up.
const KNOWN_USER = 'alice';
const KNOWN_PASSWORD = 'password123';

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.json());

vuln.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === KNOWN_USER && password === KNOWN_PASSWORD) {
    return res.json({ ok: true });
  }
  // The bug is the SILENCE. A failed login is a security-relevant event, and we
  // do nothing: no log line, no counter. 50 000 attempts look like zero.
  return res.status(401).json({ ok: false });
});

vuln.post('/audit', (req, res) => {
  const username = (req.body && req.body.username) || '';
  // Untrusted input concatenated into a line-oriented log. A newline in
  // `username` forges an entirely separate, attacker-controlled log line.
  vulnLog.push(`${new Date().toISOString()} INFO login attempt user=${username}`);
  res.json({ logged: true });
});

vuln.post('/checkout', (req, res) => {
  // Dumps the WHOLE body into the log — card numbers, CVVs, tokens and all.
  vulnLog.push(`${new Date().toISOString()} INFO checkout ${JSON.stringify(req.body || {})}`);
  res.json({ ok: true });
});

// The raw log, as text — this is what an operator would `tail`.
vuln.get('/logs', (req, res) => {
  res.type('text/plain').send(vulnLog.join('\n'));
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.json());

// Keys whose VALUES must never be logged. Matched case-insensitively anywhere
// in the key name, so "cardNumber", "authorization", "user_password" all hit.
const SENSITIVE_KEY = /password|secret|token|card|cvv|ssn|authorization/i;

/** Deep-copy an object, replacing sensitive values with a marker. */
function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redact(v);
    }
    return out;
  }
  return value;
}

/**
 * The one place a structured record enters the log. Every field is a JSON
 * value, so an embedded newline in user data is escaped by JSON.stringify and
 * stays INSIDE its field — log injection is neutralised by construction. We
 * store objects and serialise on read (JSONL), which is what a real log
 * pipeline ships to Loki/Elasticsearch.
 */
function record(event, fields) {
  const entry = { ts: new Date().toISOString(), event, ...redact(fields) };
  safeLog.push(entry);
  return entry;
}

safe.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const ok = username === KNOWN_USER && password === KNOWN_PASSWORD;

  // EVERY attempt is counted — success and failure — so the dashboard reflects
  // reality. This is the counter Grafana graphs.
  metrics.authAttempts.inc({ result: ok ? 'success' : 'failure' });

  if (ok) {
    failuresByUser.delete(username);
    record('auth.success', { username, password });   // password gets redacted
    return res.json({ ok: true });
  }

  // Structured, redacted failure record — parseable, safe, attributable.
  record('auth.failed', { username, password });

  // Per-user brute-force detection. Cross the threshold once and we ALERT:
  // bump the security-alert counter (Grafana), keep an alert record, and expose
  // it so on-call can see it. This is the "alerting", not just "monitoring".
  const n = (failuresByUser.get(username) || 0) + 1;
  failuresByUser.set(username, n);
  if (n >= BRUTE_FORCE_THRESHOLD) {
    metrics.securityAlerts.inc({ kind: 'brute_force' });
    const alert = record('ALERT.brute_force_suspected', { username, failureCount: n });
    safeAlerts.push(alert);
  }

  return res.status(401).json({ ok: false });
});

safe.post('/checkout', (req, res) => {
  // Same event, but the record is redacted first — secrets never reach disk.
  record('checkout', req.body || {});
  res.json({ ok: true });
});

safe.post('/audit', (req, res) => {
  const username = (req.body && req.body.username) || '';
  // The username is a JSON string field; a newline becomes \n, so it can't
  // forge a second record. One request → exactly one log entry.
  record('audit.login_attempt', { username });
  res.json({ logged: true });
});

// JSONL: one JSON object per line — parseable and injection-proof.
safe.get('/logs', (req, res) => {
  res.type('text/plain').send(safeLog.map((e) => JSON.stringify(e)).join('\n'));
});

// The alerts on-call would page on. On the vuln side this endpoint doesn't
// even exist — because the vuln side never detected anything.
safe.get('/alerts', (req, res) => {
  res.json({ alerts: safeAlerts });
});

module.exports = { vuln, safe };
