'use strict';
/**
 * A04:2025 — Cryptographic Failures  (▼ #2 → #4)
 *
 * It dropped a couple of places, but the failures didn't get more exotic — they
 * got more basic. The 2025 data is dominated by *weak randomness* and by using
 * a cipher mode that keeps the data secret but doesn't stop the attacker
 * *rewriting* it. Three failures here:
 *
 *   1. predictable tokens — Math.random() is not a CSPRNG
 *   2. exposing password material at all, and storing it with fast unsalted MD5
 *   3. encrypting without authenticating — AES-CBC with a static IV and no tag,
 *      which lets an attacker flip bits in the plaintext without the key
 *
 * The fixes: crypto.randomBytes, never return hashes + verify with a slow salted
 * KDF in constant time, and AES-GCM (encrypt-then-MAC) so any tampering throws.
 */
const express = require('express');
const crypto = require('node:crypto');
const { db, scryptVerify, scryptHash } = require('../db');

// One symmetric key for the seal/unseal demo, generated per process. The point
// of the CBC lab is that the attacker rewrites the plaintext WITHOUT this key.
const KEY = crypto.randomBytes(32);

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();

// BUG 1 — a "password reset token" from Math.random(). It is not a CSPRNG: the
// output is short, low-entropy and, given a few samples, predictable. Anyone who
// can predict the token owns the reset link.
vuln.get('/reset-token', (req, res) => {
  const token = Math.random().toString(36).slice(2, 10);   // <= 8 chars of guessable base36
  res.json({ token });
});

// BUG 2 — the endpoint returns password material. Even "just the hashes" is a
// breach: these are unsalted MD5, which fall to a wordlist or rainbow table in
// milliseconds. (md5('admin') === 21232f297a57a5a743894a0e4a801fc3.)
vuln.get('/password-hashes', (req, res) => {
  const rows = db.prepare('SELECT username, password_md5 FROM users').all();
  res.json({ rows });
});

// BUG 3 — AES-256-CBC with a STATIC (all-zero) IV and NO authentication tag.
// CBC gives confidentiality, not integrity: flipping a byte of ciphertext block
// N-1 flips predictable bytes of plaintext block N. So an attacker can rewrite
// "role":"user" to "role":"root" without ever knowing the key. The static IV is
// a second bug (identical plaintexts encrypt identically).
const STATIC_IV = Buffer.alloc(16, 0);
vuln.all('/seal', express.json(), (req, res) => {
  const data = (req.body && req.body.data) ?? req.query.data;
  if (data === undefined) return res.status(400).json({ error: 'pass ?data= or {data}' });
  const cipher = crypto.createCipheriv('aes-256-cbc', KEY, STATIC_IV);
  const ct = Buffer.concat([cipher.update(String(data), 'utf8'), cipher.final()]);
  res.json({ ciphertext: ct.toString('hex') });   // no IV, no tag — nothing binds the bytes
});
vuln.all('/unseal', express.json(), (req, res) => {
  const hex = (req.body && req.body.ciphertext) ?? req.query.ciphertext;
  if (!hex) return res.status(400).json({ error: 'pass ?ciphertext= or {ciphertext}' });
  const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, STATIC_IV);
  const pt = Buffer.concat([decipher.update(Buffer.from(hex, 'hex')), decipher.final()]);
  // Returns whatever decrypts — including an attacker's rewritten plaintext.
  res.json({ plaintext: pt.toString('utf8'), hex: pt.toString('hex') });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();

// FIX 1 — a CSPRNG. 32 random bytes, URL-safe. ~256 bits of entropy; not
// predictable from prior outputs.
safe.get('/reset-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('base64url');   // 43 chars, unguessable
  res.json({ token });
});

// FIX 2 — never serve password material, full stop. There is no version of this
// endpoint that is safe, so it refuses. Verification happens server-side only.
safe.get('/password-hashes', (req, res) => {
  res.status(403).json({ error: 'password material is never served' });
});

// A decoy hash so the "user not found" path does the same expensive work as the
// "found" path — that keeps response time from leaking which usernames exist.
const DECOY_SCRYPT = scryptHash('user-does-not-exist-decoy');
safe.post('/verify-password', express.json(), (req, res) => {
  const { username, password } = req.body || {};
  if (!username || password === undefined) return res.status(400).json({ error: 'username and password required' });
  const user = db.prepare('SELECT password_scrypt FROM users WHERE username = ?').get(username);
  // Always run scryptVerify (against the decoy if there's no such user) so the
  // work — and therefore the timing — is the same whether or not the user exists.
  const stored = user ? user.password_scrypt : DECOY_SCRYPT;
  const ok = scryptVerify(String(password), stored) && Boolean(user);
  res.json({ ok });
});

// FIX 3 — AES-256-GCM: a fresh random IV every time and an authentication tag.
// GCM is encrypt-then-MAC; on decrypt, any tampered byte fails the tag check and
// decipher.final() throws. Confidentiality AND integrity.
safe.all('/seal', express.json(), (req, res) => {
  const data = (req.body && req.body.data) ?? req.query.data;
  if (data === undefined) return res.status(400).json({ error: 'pass ?data= or {data}' });
  const iv = crypto.randomBytes(12);   // GCM standard nonce size; never reused with this key
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(String(data), 'utf8'), cipher.final()]);
  res.json({ iv: iv.toString('hex'), ciphertext: ct.toString('hex'), tag: cipher.getAuthTag().toString('hex') });
});
safe.all('/unseal', express.json(), (req, res) => {
  const src = (req.body && req.body.ciphertext) ? req.body : req.query;
  const { iv, ciphertext, tag } = src || {};
  if (!iv || !ciphertext || !tag) return res.status(400).json({ error: 'pass iv, ciphertext and tag' });
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const pt = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]);
    res.json({ plaintext: pt.toString('utf8') });
  } catch (err) {
    // The tag didn't verify: the bytes were tampered with. Reject, don't guess.
    res.status(400).json({ error: 'integrity check failed', detail: err.message });
  }
});

module.exports = { vuln, safe };
