'use strict';
/**
 * A07:2025 — Authentication Failures  (#7, renamed from "Identification and
 * Authentication Failures").
 *
 * Almost none of this category is the password COMPARISON. It is everything
 * around it: throttling, MFA, session handling, default credentials, and
 * reusing passwords that already leaked in a breach. The vuln login below even
 * verifies the password "correctly" — it's still hopelessly broken.
 *
 * The five failures shown here, and their fixes:
 *   - fast, unsalted md5 verify        → slow, salted scryptVerify
 *   - no throttle / no MFA             → per-account lockout after 5 failures
 *   - username oracle (distinct errors)→ ONE identical error for every failure
 *   - default & breached credentials   → breach-corpus check blocks them (403)
 *   - session fixation (id reused)     → new high-entropy id at every login
 */
const express = require('express');
const { db, md5, scryptVerify } = require('../db');
const { parseCookies } = require('../lib/util');
const sessions = require('../lib/sessions');
const { metrics } = require('../metrics');

/**
 * A tiny breach corpus. A real deployment checks a k-anonymity API (e.g. Have I
 * Been Pwned) or a downloaded hash set of hundreds of millions of passwords.
 * Note what's in here: `admin` (the default admin credential), `password123`
 * (Alice's real password), `hunter2` (Bob's), and the "long but public" ones —
 * length alone does not save a password that everyone already has.
 */
const BREACHED = new Set([
  'password123', 'admin', 'hunter2', 'qwertyuiop123456',
  'correct horse battery staple',
  '123456', '12345678', 'password', 'letmein', 'qwerty',
  'welcome', 'iloveyou', 'monkey', 'dragon', 'abc123',
]);

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.json());
vuln.use(express.urlencoded({ extended: false }));

// BUG — a login that "works" and is still broken five ways:
//   * md5 verify (fast + unsalted → offline cracking is trivial), no MFA
//   * no throttling, so credential stuffing / spraying runs unlimited
//   * DISTINCT errors for "no such user" vs "wrong password" = a username oracle
//   * the default admin/admin credential is honoured
//   * an attacker-supplied session id is REUSED after login (session fixation)
vuln.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'No such user' });          // oracle
  if (user.password_md5 !== md5(password || '')) {
    return res.status(401).json({ error: 'Incorrect password' });             // oracle
  }
  // Session fixation: if the caller planted a `sid`, we keep using it. The
  // pre-login (attacker-known) id is now an authenticated session.
  const planted = parseCookies(req).sid;
  const sid = planted ? sessions.weak.login(planted, user.id) : sessions.weak.create(user.id);
  res.setHeader('Set-Cookie', `sid=${sid}`);
  res.json({ loggedIn: true, sid, user: { id: user.id, username: user.username, role: user.role } });
});

// BUG — registration accepts any password, including breached and trivial ones.
vuln.post('/register', (req, res) => {
  const { username, password } = req.body;
  res.json({ registered: true, username, passwordLength: (password || '').length });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.json());
safe.use(express.urlencoded({ extended: false }));

// Per-account failure counter for lockout. A real app stores this in the DB or
// a rate-limit store (redis) and also rate-limits per IP; an in-memory Map is
// the smallest honest form of the idea for one process.
const failures = new Map();
const LOCKOUT_THRESHOLD = 5;

// FIX — one identical error for EVERY failure mode. Never reveal which of
// username/password was wrong, or whether the account exists.
const GENERIC_ERROR = 'Invalid username or password.';

safe.post('/login', (req, res) => {
  const { username, password } = req.body;

  // FIX — lockout BEFORE any password work. Repeated failures against one
  // account stop getting attempts (429), which defeats spraying/stuffing.
  const fails = failures.get(username) || 0;
  if (fails >= LOCKOUT_THRESHOLD) {
    metrics.authAttempts.inc({ result: 'lockout' });
    metrics.securityAlerts.inc({ kind: 'brute_force' });
    return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  // FIX — scryptVerify: salted + deliberately slow, and constant-time. We run
  // it even when the user is missing would be ideal; here we simply return the
  // one generic error so the response can't distinguish the two cases.
  const ok = user && scryptVerify(password || '', user.password_scrypt);

  if (!ok) {
    failures.set(username, fails + 1);
    metrics.authAttempts.inc({ result: 'failure' });
    return res.status(401).json({ error: GENERIC_ERROR });
  }

  // FIX — a correct password that appears in the breach corpus is NOT accepted.
  // This is the control that actually stops admin/admin: rate limiting doesn't
  // save you from a valid default credential, but refusing breached passwords
  // does. The user must rotate it before they can log in.
  if (BREACHED.has(password)) {
    metrics.authAttempts.inc({ result: 'breached' });
    return res.status(403).json({ error: 'This password appeared in a breach. You must reset it.', mustResetPassword: true });
  }

  // Success. Clear the failure counter and FIX session fixation by minting a
  // brand-new high-entropy id (rotate on every privilege change), destroying
  // whatever id the client presented.
  failures.delete(username);
  const oldSid = parseCookies(req).sid;
  const sid = sessions.strong.login(oldSid, user.id);
  // httpOnly (no JS access), secure (HTTPS only), sameSite (CSRF hardening).
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/`);
  metrics.authAttempts.inc({ result: 'success' });
  res.json({ loggedIn: true, user: { id: user.id, username: user.username, role: user.role } });
});

// FIX — registration rejects breached passwords FIRST, then enforces a length
// floor. Length beats composition rules; "at least 12 characters" plus a breach
// check is the modern NIST-aligned policy.
safe.post('/register', (req, res) => {
  const { username, password } = req.body;
  const pw = password || '';
  if (BREACHED.has(pw)) {
    return res.status(400).json({ error: 'That password has appeared in a breach corpus. Choose another.' });
  }
  if (pw.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  }
  res.json({ registered: true, username });
});

// FIX — server-side logout actually destroys the session, so a stolen cookie
// is worthless afterwards. (The vuln side has no logout at all.)
safe.post('/logout', (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.strong.destroy(sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ loggedOut: true });
});

module.exports = { vuln, safe };
