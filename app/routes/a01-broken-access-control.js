'use strict';
/**
 * A01:2025 — Broken Access Control  (#1, unchanged from 2021)
 *
 * "Access control enforces policy such that users cannot act outside of their
 *  intended permissions." Failures: read/modify others' data, or reach
 *  functions you shouldn't.
 *
 * This lab covers the four OWASP example shapes plus SSRF, which was folded
 * into A01 for 2025 (CWE-918):
 *   1. IDOR (parameter tampering)         3. client-side-only control
 *   2. forced browsing to a function      4. SSRF via a "fetch this URL" feature
 */
const express = require('express');
const { db } = require('../db');
const { parseCookies, escapeHtml } = require('../lib/util');
const { assertPublicUrl } = require('../lib/ssrf-guard');
const { metrics } = require('../metrics');

// Pretend login: `?as=alice` or a `who` cookie decides who you are. Real apps
// use a session; the authorization bugs below are identical either way.
function whoami(req) {
  const name = req.query.as || parseCookies(req).who || 'alice';
  return db.prepare('SELECT * FROM users WHERE username = ?').get(name) || null;
}

async function fetchUrl(target, { guard = null } = {}) {
  if (guard) await guard(target);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const r = await fetch(target, { signal: controller.signal, redirect: 'manual' });
    const body = (await r.text()).slice(0, 2000);
    return { status: r.status, body };
  } finally { clearTimeout(timer); }
}

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();

// BUG 1 — IDOR. The invoice id comes from the URL and is trusted completely.
vuln.get('/invoices/:id', (req, res) => {
  const user = whoami(req);
  if (!user) return res.status(401).json({ error: 'log in first' });
  const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if (!invoice) return res.status(404).json({ error: 'no such invoice' });
  // Missing "...AND user_id = ?". That single omission is the whole bug.
  res.json({ viewer: user.username, invoice });
});

// BUG 2 — forced browsing. The admin page is not linked, and that is the only
// thing "protecting" it. Obscurity is not access control.
vuln.get('/admin/users', (req, res) => {
  res.json({ users: db.prepare('SELECT id, username, email, role FROM users').all() });
});

// BUG 3 — client-side-only control. The UI hides the delete button for
// non-admins, but the endpoint never checks the role, so curl wins.
vuln.post('/invoices/purge', (req, res) => {
  res.json({ ok: true, wouldHaveDeleted: db.prepare('SELECT COUNT(*) c FROM invoices').get().c });
});

// BUG 4 — SSRF. The webhook/link-unfurl feature fetches whatever URL the user
// gives it, from inside the network, with no validation. Point it at
// http://internal-api:8081/internal/admin/flag or the cloud metadata service.
vuln.all('/unfurl', express.json(), async (req, res) => {
  const target = req.query.url || (req.body && req.body.url);
  if (!target) return res.status(400).json({ error: 'pass ?url=' });
  metrics.ssrfAttempts.inc({ result: 'allowed' });
  try {
    const out = await fetchUrl(target);
    res.json({ fetched: target, ...out });
  } catch (err) {
    res.status(502).json({ fetched: target, error: err.message });
  }
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();

// Deny by default: everything here needs an identity.
safe.use((req, res, next) => {
  const user = whoami(req);
  if (!user) return res.status(401).json({ error: 'authentication required' });
  req.user = user;
  next();
});

// One reusable, declarative check — implemented once, used everywhere.
const requireRole = (role) => (req, res, next) =>
  req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });

// FIX 1 — enforce record ownership in the query itself.
safe.get('/invoices/:id', (req, res) => {
  const invoice = db.prepare('SELECT * FROM invoices WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  if (!invoice) {
    metrics.accessDenied.inc({ resource: 'invoice' });        // A09: log/alert on denials
    console.warn(JSON.stringify({ event: 'access_control.denied', actor: req.user.username, resource: `invoice:${req.params.id}` }));
    // 404, not 403: a 403 confirms the record exists and leaks the id space.
    return res.status(404).json({ error: 'no such invoice' });
  }
  res.json({ viewer: req.user.username, invoice });
});

// FIX 2 & 3 — the server enforces the role, whatever the UI shows.
safe.get('/admin/users', requireRole('admin'), (req, res) => {
  res.json({ users: db.prepare('SELECT id, username, email, role FROM users').all() });
});
safe.post('/invoices/purge', requireRole('admin'), (req, res) => {
  res.json({ ok: true, wouldHaveDeleted: db.prepare('SELECT COUNT(*) c FROM invoices').get().c });
});

// FIX 4 — validate the SSRF target: http/https only, and reject any hostname
// that resolves to a private/loopback/link-local/metadata address. Resolving
// before fetching is what defeats DNS rebinding.
safe.all('/unfurl', express.json(), async (req, res) => {
  const target = req.query.url || (req.body && req.body.url);
  if (!target) return res.status(400).json({ error: 'pass ?url=' });
  try {
    const out = await fetchUrl(target, { guard: assertPublicUrl });
    metrics.ssrfAttempts.inc({ result: 'allowed' });
    res.json({ fetched: target, ...out });
  } catch (err) {
    metrics.ssrfAttempts.inc({ result: 'blocked' });
    console.warn(JSON.stringify({ event: 'ssrf.blocked', actor: req.user.username, target, reason: err.message }));
    res.status(400).json({ error: `refused to fetch: ${err.message}` });
  }
});

module.exports = { vuln, safe };
