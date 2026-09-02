'use strict';
/**
 * A05:2025 — Injection  (#3 in 2021 → #5 in 2025)
 *
 * "An application is vulnerable when user-supplied data is not validated,
 *  filtered, or sanitized, and is sent to an interpreter as part of a command
 *  or query." The interpreter runs the attacker's *code* because we handed it
 *  what we thought was *data*.
 *
 * XSS moved INTO this category for 2025 (30,000+ CVEs of its own): the browser
 * is just one more interpreter, and HTML/JS is one more grammar you can inject.
 *
 * This lab covers four interpreters, each as a vuln/safe pair at the same path:
 *   1. SQL — login (authentication bypass via a comment)
 *   2. SQL — search over invoice memos (UNION-based data exfiltration)
 *   3. OS shell — a "ping this host" tool (command chaining)
 *   4. HTML — reflected XSS (/echo) AND stored XSS (/guestbook)
 *
 * The fix has ONE shape every time: keep untrusted input in the DATA channel,
 * never the CODE channel. Bind SQL parameters; pass argv, not a shell string;
 * encode for the HTML context you're writing into.
 */
const express = require('express');
const { db, md5 } = require('../db');
const { execFile, exec } = require('node:child_process');
const { escapeHtml } = require('../lib/util');

// Both routers read/write the SAME seeded tables (the singleton db), so a
// payload stored through one side is visible to the other — that is the point
// of stored XSS: it crosses users, and here it crosses the vuln/safe boundary
// too, which makes the "renders raw vs encoded" contrast easy to see.
function renderGuestbook(rows, { encode }) {
  const entries = rows.map((r) => {
    // VULN passes body straight through; SAFE runs it through escapeHtml first.
    const body = encode ? escapeHtml(r.body) : r.body;
    const author = encode ? escapeHtml(r.author) : r.author;
    return `<li><b>${author}</b>: ${body}</li>`;
  }).join('\n');
  return `<!doctype html><html><body><h1>Guestbook</h1><ul>\n${entries}\n</ul></body></html>`;
}

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.urlencoded({ extended: false }));
vuln.use(express.json());

// BUG 1 — SQL injection in LOGIN. The username and password are concatenated
// straight into the query text, so `admin'--` closes the string and comments
// out the password check. No password required.
vuln.post('/login', (req, res) => {
  const u = req.body.username || '';
  const p = req.body.password || '';
  const sql = `SELECT * FROM users WHERE username='${u}' AND password_md5='${md5(p)}'`;
  try {
    const user = db.prepare(sql).get();
    if (user) return res.json({ loggedIn: true, user: { id: user.id, username: user.username, role: user.role } });
    res.json({ loggedIn: false });
  } catch (err) {
    // A syntax error in the injected SQL still leaks that injection is possible.
    res.status(200).json({ loggedIn: false, error: err.message });
  }
});

// BUG 2 — SQL injection in SEARCH. The term is concatenated into a LIKE clause,
// so a UNION SELECT with a matching column count grafts rows from ANOTHER table
// (users) onto the invoice result set. Usernames + hashes leak through `memo`.
vuln.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Column order matters for a UNION attack: the attacker aligns their columns
  // to ours, so `memo` sits where their injected `username` lands.
  const sql = `SELECT id, memo, amount_cents, user_id FROM invoices WHERE memo LIKE '%${q}%'`;
  try {
    const rows = db.prepare(sql).all();
    res.json({ rows });
  } catch (err) {
    res.status(200).json({ rows: [], error: err.message });
  }
});

// BUG 3 — OS command injection. The host is interpolated into a shell string,
// so `localhost;echo INJECTED` runs a SECOND command. exec() spawns /bin/sh -c.
vuln.get('/ping', (req, res) => {
  const host = req.query.host || '';
  exec(`ping -c 1 ${host}`, { timeout: 3000 }, (err, stdout, stderr) => {
    // We echo everything back so the injected command's output is visible.
    res.type('text/plain').send(`${stdout || ''}${stderr || ''}${err ? err.message : ''}`);
  });
});

// BUG 4a — reflected XSS. The query value is written into the HTML response
// with no encoding, so a <script> tag in the URL executes in the victim's page.
vuln.get('/echo', (req, res) => {
  const q = req.query.q || '';
  res.type('html').send(`<!doctype html><html><body><p>You searched for: ${q}</p></body></html>`);
});

// BUG 4b — stored XSS. The payload is saved once; it then executes for EVERY
// later viewer of the guestbook — including the support agent's admin view.
vuln.post('/guestbook', (req, res) => {
  const author = req.body.author || 'anon';
  const body = req.body.body || '';
  db.prepare('INSERT INTO guestbook (author, body) VALUES (?, ?)').run(author, body);
  res.json({ ok: true });
});
vuln.get('/guestbook', (req, res) => {
  const rows = db.prepare('SELECT author, body FROM guestbook ORDER BY id').all();
  res.type('html').send(renderGuestbook(rows, { encode: false }));   // raw — the bug
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.urlencoded({ extended: false }));
safe.use(express.json());

// A Content-Security-Policy is defence-in-depth for the XSS routes: even if an
// encoding bug slips through, `script-src 'self'` refuses inline/injected JS.
function withCsp(res) {
  res.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'");
  return res;
}

// FIX 1 — parameterised login. The `?` placeholders keep username/password in
// the DATA channel; the driver never re-parses them as SQL. `admin'--` is now
// just a username that does not exist, so the login fails.
safe.post('/login', (req, res) => {
  const u = req.body.username || '';
  const p = req.body.password || '';
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?').get(u, md5(p));
  if (user) return res.json({ loggedIn: true, user: { id: user.id, username: user.username, role: user.role } });
  res.json({ loggedIn: false });
});

// FIX 2 — parameterised search. The term is bound as a single LIKE literal, so
// a UNION payload is matched as text (and matches nothing) rather than executed.
safe.get('/search', (req, res) => {
  const q = req.query.q || '';
  const rows = db.prepare('SELECT id, user_id, amount_cents, memo FROM invoices WHERE memo LIKE ?').all(`%${q}%`);
  res.json({ rows });
});

// FIX 3 — no shell. execFile passes argv directly to the ping binary, so there
// is no shell to interpret `;` or `|`. Plus a positive allow-list: a hostname
// is letters/digits/dots/hyphens and nothing else — reject everything else.
const HOSTNAME = /^[a-zA-Z0-9.-]+$/;
safe.get('/ping', (req, res) => {
  const host = req.query.host || '';
  if (!HOSTNAME.test(host)) {
    return res.status(400).type('text/plain').send('invalid hostname');
  }
  execFile('ping', ['-c', '1', host], { timeout: 3000 }, (err, stdout, stderr) => {
    res.type('text/plain').send(`${stdout || ''}${stderr || ''}${err ? String(err.message) : ''}`);
  });
});

// FIX 4a — reflected XSS: encode for the HTML text-node context before writing.
safe.get('/echo', (req, res) => {
  const q = req.query.q || '';
  withCsp(res).type('html').send(`<!doctype html><html><body><p>You searched for: ${escapeHtml(q)}</p></body></html>`);
});

// FIX 4b — stored XSS: encode on OUTPUT. (Storing raw and encoding at render is
// correct — the same stored value may be shown in several different contexts.)
safe.post('/guestbook', (req, res) => {
  const author = req.body.author || 'anon';
  const body = req.body.body || '';
  db.prepare('INSERT INTO guestbook (author, body) VALUES (?, ?)').run(author, body);
  res.json({ ok: true });
});
safe.get('/guestbook', (req, res) => {
  const rows = db.prepare('SELECT author, body FROM guestbook ORDER BY id').all();
  withCsp(res).type('html').send(renderGuestbook(rows, { encode: true }));  // encoded — the fix
});

module.exports = { vuln, safe };
