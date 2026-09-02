'use strict';
/**
 * A10:2025 — Mishandling of Exceptional Conditions  (BRAND NEW for 2025)
 *
 * The new entry. It's about what your code does when something goes WRONG:
 *   - Fail OPEN — an error in a security check is swallowed and treated as
 *     "allow". The one time your authz service hiccups, everyone's an admin.
 *   - Leak internals — handing the caller err.message + err.stack turns an
 *     exception into a reconnaissance gift (schema, paths, versions).
 *   - No atomicity — a multi-step operation that throws halfway leaves the
 *     world half-changed (money debited but never credited).
 *
 * The fixes are the opposite of each: fail CLOSED, return an opaque reference,
 * and wrap multi-step writes in a transaction that rolls back as a unit.
 */
const express = require('express');
const crypto = require('node:crypto');
const { db } = require('../db');

// A flaky internal permission service, modelled as a module-level toggle. Flip
// it "down" and the check throws — simulating a timeout / connection refused.
// Shared by both routers so a single POST toggles the whole lab.
let authzUp = true;

/**
 * The permission check. When the service is up it answers correctly: only the
 * admin (seeded userId 4) may perform admin actions. When it's down it THROWS —
 * and how each side handles that throw is the entire lesson.
 */
function permissionCheck(userId) {
  if (!authzUp) throw new Error('authz-service: connection refused (ECONNREFUSED)');
  return Number(userId) === 4;
}

// Shared control + read endpoints, registered on both routers below.
function attachShared(router) {
  // Toggle the flaky service up/down for the demo.
  router.post('/authz-service/:state', (req, res) => {
    authzUp = req.params.state !== 'down';
    res.json({ authzUp });
  });

  // Ground truth for the money labs: every account balance and the system
  // total. In a correct system the total is CONSERVED across any transfer.
  router.get('/balances', (req, res) => {
    const accounts = db.prepare('SELECT user_id, balance_cents FROM accounts ORDER BY user_id').all();
    const total = accounts.reduce((sum, a) => sum + a.balance_cents, 0);
    res.json({ accounts, total });
  });
}

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.json());
attachShared(vuln);

vuln.post('/admin-action', (req, res) => {
  const userId = req.query.userId || (req.body && req.body.userId);
  let allowed;
  try {
    allowed = permissionCheck(userId);
  } catch (err) {
    // FAIL OPEN — the catch treats "we couldn't check" as "yes". The moment the
    // authz service blips, every caller becomes an admin.
    allowed = true;
  }
  if (!allowed) return res.status(403).json({ error: 'forbidden' });
  res.json({ allowed: true, action: 'performed' });
});

vuln.get('/report', (req, res) => {
  const table = req.query.table || '';
  try {
    // SQL identifier interpolation (its own bug), but the A10 point is the
    // catch: on any error we hand the client the message AND the stack.
    const rows = db.prepare(`SELECT * FROM ${table}`).all();
    res.json({ rows });
  } catch (err) {
    // Reconnaissance gift: schema hints, file paths, library internals.
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

vuln.post('/transfer', (req, res) => {
  const { fromUserId, toUserId, amountCents } = req.body || {};
  const amount = Number(amountCents);
  const failMidway = req.query.failMidway === '1';

  // Two separate writes, NO transaction. Debit first...
  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?').run(amount, fromUserId);
  if (failMidway) {
    // ...then "downstream" blows up. We already took the money and we never put
    // it back — it simply vanishes. The total drops.
    return res.status(500).json({ error: 'downstream failure after debit' });
  }
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, toUserId);
  res.json({ ok: true });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.json());
attachShared(safe);

safe.post('/admin-action', (req, res) => {
  const userId = req.query.userId || (req.body && req.body.userId);
  let allowed;
  try {
    allowed = permissionCheck(userId);
  } catch (err) {
    // FAIL CLOSED — if we cannot confirm you're allowed, the answer is "no".
    // 503, because this is our outage, not the caller's fault; they can retry.
    console.warn(JSON.stringify({ event: 'authz.unavailable', reason: err.message }));
    return res.status(503).json({ error: 'authorization service unavailable' });
  }
  if (!allowed) return res.status(403).json({ error: 'forbidden' });
  res.json({ allowed: true, action: 'performed' });
});

// Only these identifiers are ever allowed near the query — an allow-list, not a
// sanitiser. Anything else is rejected before we touch the database.
const REPORTABLE_TABLES = new Set(['invoices', 'accounts']);

safe.get('/report', (req, res) => {
  const table = req.query.table || '';
  if (!REPORTABLE_TABLES.has(table)) {
    // Known, expected condition → a clean 400. We still return a reference and
    // NO stack, so probing the endpoint yields nothing useful.
    return res.status(400).json({ error: 'unknown report', reference: crypto.randomUUID() });
  }
  try {
    // Safe: `table` is one of a fixed, code-controlled set of literals.
    const rows = db.prepare(`SELECT * FROM ${table}`).all();
    res.json({ rows });
  } catch (err) {
    // The real error is logged server-side under a reference the client also
    // gets. Support can correlate; an attacker learns nothing.
    const reference = crypto.randomUUID();
    console.error(JSON.stringify({ event: 'report.error', reference, detail: err.message }));
    res.status(500).json({ error: 'internal error', reference });
  }
});

safe.post('/transfer', (req, res) => {
  const { fromUserId, toUserId, amountCents } = req.body || {};
  const amount = Number(amountCents);
  const failMidway = req.query.failMidway === '1';

  // ONE transaction. better-sqlite3 runs the function atomically: any throw
  // rolls back every write inside it, so the money is never half-moved.
  const doTransfer = db.transaction(() => {
    const from = db.prepare('SELECT balance_cents FROM accounts WHERE user_id = ?').get(fromUserId);
    if (!from) throw new Error('no such source account');
    // Guard the invariant: never let a balance go negative.
    if (from.balance_cents < amount) throw new Error('insufficient funds');

    db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?').run(amount, fromUserId);
    // Same injectable failure point as the vuln — but here the throw unwinds
    // the debit too, so balances are conserved.
    if (failMidway) throw new Error('downstream failure after debit');
    db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, toUserId);
  });

  try {
    doTransfer();
    res.json({ ok: true });
  } catch (err) {
    const reference = crypto.randomUUID();
    console.error(JSON.stringify({ event: 'transfer.rolled_back', reference, detail: err.message }));
    res.status(409).json({ error: 'transfer failed and was rolled back', reference });
  }
});

module.exports = { vuln, safe };
