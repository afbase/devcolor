'use strict';
/**
 * A06:2025 — Insecure Design  (#4 in 2021 → #6 in 2025)
 *
 * These are flaws in the PLAN, not the code. The code below is bug-free in the
 * ordinary sense — it does exactly what it was designed to do. The design just
 * never stated the rule that makes the feature safe, so no amount of input
 * validation or patching fixes it. You catch these by threat-modelling the
 * critical flows (auth, access control, money) BEFORE you build them.
 *
 *   1. /checkout — coupon stacking: each use is valid; the sequence is abuse.
 *   2. /refund   — no invariant: "never pay out more than was charged" is unstated.
 *   3. /recover  — knowledge-based recovery: a guessable secret is not a secret.
 *
 * The SECURE side doesn't add a filter — it states the missing rule and enforces
 * it at the operation, atomically, on the server.
 */
const express = require('express');
const crypto = require('node:crypto');
const { db } = require('../db');

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.json());

// BUG 1 — coupon stacking. The design said "WELCOME10 is 10% off" but never
// "one coupon per order" or "each coupon is consumable". So every entry in the
// array is applied. Ten 10%-off coupons drive the order to (near) free.
vuln.post('/checkout', (req, res) => {
  const price = Number(req.body.priceCents) || 0;
  const codes = Array.isArray(req.body.coupons) ? req.body.coupons : [];
  let percent = 0;
  for (const code of codes) {
    const c = db.prepare('SELECT percent_off FROM coupons WHERE code = ?').get(code);
    if (c) percent += c.percent_off;          // additive, uncapped-per-code, unconsumed
  }
  const total = Math.max(0, Math.round(price * (1 - Math.min(percent, 100) / 100)));
  res.json({ totalCents: total, appliedPercent: percent });
});

// BUG 2 — no invariant on the refund. Nothing ties the payout to a real charge,
// so refunding more than was ever paid just increases the balance.
vuln.post('/refund', (req, res) => {
  const userId = Number(req.body.userId);
  const amount = Number(req.body.amountCents) || 0;
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, userId);
  const balance = db.prepare('SELECT user_id, balance_cents FROM accounts WHERE user_id = ?').get(userId);
  res.json({ ok: true, balance });
});

// BUG 3 — knowledge-based account recovery. A "security question" is public
// information, so guessing a common surname yields a password-reset token.
vuln.post('/recover', (req, res) => {
  const maiden = String(req.body.motherMaidenName || '').toLowerCase();
  if (maiden === 'smith') {
    const token = crypto.randomBytes(16).toString('hex');
    return res.json({ ok: true, resetToken: token });
  }
  res.status(401).json({ ok: false, error: 'wrong answer' });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.json());

// FIX 1 — state the rule, enforce it server-side, consume the coupon ATOMICALLY.
// "At most one coupon per order" is now explicit, and the UPDATE ... WHERE
// times_used < max_uses both checks and consumes in a single statement, so two
// concurrent requests can't both slip under the cap (no check-then-act race).
safe.post('/checkout', (req, res) => {
  const price = Number(req.body.priceCents) || 0;
  const codes = Array.isArray(req.body.coupons) ? req.body.coupons : [];
  if (codes.length > 1) {
    return res.status(400).json({ error: 'at most one coupon per order' });
  }
  if (codes.length === 0) {
    return res.json({ totalCents: price, appliedPercent: 0 });
  }
  const code = codes[0];
  const coupon = db.prepare('SELECT percent_off FROM coupons WHERE code = ?').get(code);
  if (!coupon) return res.status(400).json({ error: 'unknown coupon' });
  // Atomic consume: only succeeds while uses remain.
  const consumed = db.prepare('UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses').run(code);
  if (consumed.changes === 0) {
    return res.status(400).json({ error: 'coupon has already been used' });
  }
  const total = Math.max(0, Math.round(price * (1 - coupon.percent_off / 100)));
  res.json({ totalCents: total, appliedPercent: coupon.percent_off });
});

// FIX 2 — the invariant lives next to the operation. A refund must reference a
// specific invoice that BELONGS to the user (404 otherwise, which also avoids
// leaking other users' invoice ids) and can never exceed what that invoice
// charged (400 otherwise).
safe.post('/refund', (req, res) => {
  const userId = Number(req.body.userId);
  const invoiceId = Number(req.body.invoiceId);
  const amount = Number(req.body.amountCents) || 0;
  const invoice = db.prepare('SELECT id, user_id, amount_cents FROM invoices WHERE id = ? AND user_id = ?').get(invoiceId, userId);
  if (!invoice) return res.status(404).json({ error: 'no such invoice' });
  if (amount <= 0 || amount > invoice.amount_cents) {
    return res.status(400).json({ error: 'refund exceeds the invoice amount' });
  }
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, userId);
  const balance = db.prepare('SELECT user_id, balance_cents FROM accounts WHERE user_id = ?').get(userId);
  res.json({ ok: true, balance });
});

// FIX 3 — recovery through a channel the user controls, and NO oracle. The
// response is identical whether or not the account exists, so it can't be used
// to enumerate accounts, and it never returns a token in-band.
safe.post('/recover', (req, res) => {
  // A real app would look the user up and, IF they exist, email a single-use
  // expiring token to the address on file. It would NOT branch its response on
  // whether the account exists, and it would NOT accept a "security question".
  res.json({ ok: true, message: 'If that account exists, we have sent reset instructions.' });
});

module.exports = { vuln, safe };
