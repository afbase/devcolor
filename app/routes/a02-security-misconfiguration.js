'use strict';
/**
 * A02:2025 — Security Misconfiguration  (▲ #5 → #2, the biggest mover)
 *
 * The application code can be flawless and you can still be owned by a default
 * you never changed: a verbose header, a directory you forgot was listable, a
 * debug endpoint left on, a stack trace mailed to the attacker, a cookie with
 * no flags. The 2025 data backs this up — *some* misconfiguration showed up in
 * effectively every application tested. None of these bugs are clever. They are
 * all "the framework/OS default was insecure and nobody flipped the switch."
 *
 * This lab is five defaults, broken then flipped:
 *   1. fingerprinting headers  (X-Powered-By / Server tell the attacker what to exploit)
 *   2. a listable static dir leaking a forgotten `.env.backup`
 *   3. a /debug endpoint that dumps the whole environment
 *   4. an error handler that returns the stack trace to the client
 *   5. a session cookie with no HttpOnly / Secure / SameSite
 */
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// --- Set the stage: a "public files" folder with a file that should never have
// shipped. Real incidents look exactly like this: a hurried `cp .env .env.backup`
// before an edit, then the whole folder gets served static. We materialise it at
// require time so the lab is self-contained (no fixtures to commit).
const PUBLIC_FILES_DIR = path.join(__dirname, '..', 'public-files');
fs.mkdirSync(PUBLIC_FILES_DIR, { recursive: true });
fs.writeFileSync(path.join(PUBLIC_FILES_DIR, 'brochure.txt'),
  'ACME Corp — public product brochure. Nothing secret in here.\n');
// Fake secrets — this file is bait, not real credentials.
fs.writeFileSync(path.join(PUBLIC_FILES_DIR, '.env.backup'),
  [
    '# leftover backup of the production .env — should NEVER be web-served',
    'STRIPE_KEY=sk_live_EXAMPLE_ONLY_not_a_real_key_xxxx',
    'DATABASE_URL=postgres://app:s3cr3t@db.internal:5432/prod',
    'SESSION_SECRET=hunter2-do-not-reuse',
    '',
  ].join('\n'));

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();

// BUG 1 — fingerprinting. Every response advertises the framework and server
// version. That doesn't break you by itself, but it hands the attacker the exact
// CVE list to try. Defaults like Express's X-Powered-By do this for free.
vuln.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express');
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  next();
});

// BUG 2 — a static directory with listing enabled AND dotfiles allowed. The
// forgotten `.env.backup` is now downloadable by anyone who guesses (or reads
// the listing for) the name. `dotfiles: 'allow'` is the specific footgun.
vuln.get('/files/', (req, res) => {
  const entries = fs.readdirSync(PUBLIC_FILES_DIR);
  const links = entries.map((f) => `<li><a href="${f}">${f}</a></li>`).join('');
  res.type('html').send(`<h1>Index of /files</h1><ul>${links}</ul>`);
});
vuln.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'allow', index: false }));

// BUG 3 — a debug endpoint that dumps process.env. Handy in development, fatal
// in production: it leaks every secret the process was started with.
vuln.get('/debug', (req, res) => {
  res.json({ env: process.env });
});

// BUG 4 — the error handler returns the stack trace. Stack traces leak file
// paths, library versions and sometimes secrets baked into error messages.
vuln.get('/boom', (req, res) => {
  throw new Error('database connection to db.internal:5432 failed: password authentication failed for user "app"');
});
// eslint-disable-next-line no-unused-vars
vuln.use((err, req, res, next) => {
  res.status(500).type('text').send(err.stack);   // <-- the whole point: err.stack to the client
});

// BUG 5 — a session cookie with no security attributes. No HttpOnly (JS can read
// it → XSS steals the session), no Secure (sent over plain HTTP), no SameSite
// (sent cross-site → CSRF). We set the header by hand so nothing adds flags.
vuln.get('/login-demo', (req, res) => {
  res.setHeader('Set-Cookie', 'demo_session=s3ssion-abc123; Path=/');
  res.json({ ok: true, note: 'inspect the Set-Cookie header' });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();

// FIX 1 — strip the fingerprint and add the baseline security response headers.
// In a real app you'd use `helmet`; these are the headers it sets, spelled out
// so you can see WHAT each one buys you. Comments are the lesson.
safe.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); // force HTTPS
  res.setHeader('X-Content-Type-Options', 'nosniff');                                 // no MIME sniffing
  res.setHeader('Referrer-Policy', 'no-referrer');                                    // don't leak URLs
  res.setHeader('X-Frame-Options', 'DENY');                                           // no clickjacking
  next();
});

// FIX 2 — serve the folder with listing OFF and dotfiles IGNORED. The brochure
// is still public; `.env.backup` and the directory index are 404. (Better still:
// don't keep secrets under a web root at all — but defense in depth.)
safe.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'ignore', index: false }));
// No '/files/' listing handler exists, so the directory index falls through to 404.

// FIX 3 — the debug endpoint simply does not exist in production. It is mounted
// only behind an explicit opt-in env flag, so the default (unset) is safe.
if (process.env.ENABLE_DEBUG_ENDPOINTS === '1') {
  safe.get('/debug', (req, res) => res.json({ env: process.env }));
}

// FIX 4 — on error, log the detail server-side (where responders can see it) and
// return an opaque reference id to the client. The user can quote the id in a
// support ticket; the attacker learns nothing.
safe.get('/boom', (req, res) => {
  throw new Error('database connection to db.internal:5432 failed: password authentication failed for user "app"');
});
// eslint-disable-next-line no-unused-vars
safe.use((err, req, res, next) => {
  const reference = crypto.randomUUID();
  console.error(JSON.stringify({ event: 'unhandled_error', reference, message: err.message, stack: err.stack }));
  res.status(500).json({ error: 'Internal server error', reference });
});

// FIX 5 — set every cookie flag: HttpOnly (JS can't read it), Secure (HTTPS
// only), SameSite=Lax (not sent on cross-site requests). Express's res.cookie
// serialises these for us.
safe.get('/login-demo', (req, res) => {
  res.cookie('demo_session', 's3ssion-abc123', {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/',
  });
  res.json({ ok: true, note: 'inspect the Set-Cookie header' });
});

module.exports = { vuln, safe };
