'use strict';
// A10:2025 — Mishandling of Exceptional Conditions (brand new). Front-end module.
// Persona: an engineer whose error handling always picks the worst option —
// fail open, leak the stack, skip the transaction. The profile page IS the live
// target — each bench action hits /vuln/a10 and /safe/a10
// (see app/routes/a10-exceptional-conditions.js).
module.exports = {
  persona: {
    name: 'Cat Chandler',
    title: 'Principal Engineer, Error Handling at FailOpen',
    company: 'FailOpen',
    avatar: 'CC',
    color: '#c0392b',
    banner: 'linear-gradient(120deg,#3d0a06,#c0392b 58%,#f1948a)',
    location: 'The catch { } block',
    connections: '503 (Service Unavailable)',
  },
  post: {
    time: '1h',
    reactions: 133, comments: 58, reposts: 21,
    headline: 'FailOpen: when in doubt, allow it',
    cta: 'Fail open, leak the stack, and never wrap a transaction',
    summary: `Error paths that pick the least safe option: failing open when a security check itself errors out, returning a full stack trace to the client instead of an opaque message, or leaving a multi-step write half-finished when the second step fails.`,
  },
  profile: {
    headline: 'Principal Engineer, Error Handling @ FailOpen · catch { allow: true }',
    about: `Mishandling of exceptional conditions is about what a system does once something has already gone wrong: does it fail open or closed, does the error response leak internal detail, and does a partially completed operation get rolled back or left half-done. Error paths get far less testing than the happy path, which is exactly why they tend to default to the least safe option.

The failure itself often isn't the real bug — it's the untested assumption baked into whatever happens next.

Try it below: knock a dependency offline and see whether access is granted or denied by default, throw a bad input and see what the error response reveals, or interrupt a multi-step transfer partway through and check whether the total is conserved.`,
    highlights: ['Fail-open authz', 'Stack trace leakage (CWE-209)', 'Non-atomic writes', 'Lost money on failure'],
  },
  bench: {
    intro: 'FailOpen’s error handling, live. Order matters: toggle the authz service down before the admin action, and check /balances before and after a transfer. Run each on /vuln and /safe and diff.',
    actions: [
      {
        id: 'authz-toggle',
        title: 'Toggle the authz service down / up',
        description: 'Simulate the internal permission service timing out. Set it "down" to make the permission check throw; set it "up" to restore. This flips a shared switch for the whole lab — do it on the same side you’ll test.',
        method: 'POST', path: '/authz-service/{state}',
        inputs: [{ name: 'state', label: 'state', default: 'down', options: ['down', 'up'] }],
        code: {
          lang: 'js',
          src: { vuln: { anchor: 'let authzUp = true;', to: 'function permissionCheck' } },
          intro: 'This flips a shared switch that makes the permission check throw — the setup for the next action.',
          vulnLabel: '⚙️ The flaky permission check (shared by both sides)',
          vuln: `let authzUp = true;
function permissionCheck(userId) {
  if (!authzUp) throw new Error('authz-service: connection refused (ECONNREFUSED)');
  return Number(userId) === 4;   // only the seeded admin may perform admin actions
}
// POST /authz-service/down makes the very next permissionCheck() throw`,
        },
        expect: {
          vuln: 'authzUp:false — the next admin-action will fail OPEN',
          safe: 'authzUp:false — the next admin-action will fail CLOSED',
        },
      },
      {
        id: 'admin-action',
        title: 'Perform an admin action as a non-admin',
        description: 'Run an admin-only action. With the service UP, only userId 4 (admin) is allowed. With it DOWN (toggle above), the check throws: the vuln side treats that as "allow"; the safe side refuses. Try userId 2 (a normal user) with the service down.',
        method: 'POST', path: '/admin-action',
        inputs: [{ name: 'userId', label: 'userId', default: '2', in: 'body', options: ['2', '4'] }],
        hint: 'Toggle authz DOWN first, then run this as userId 2.',
        code: {
          lang: 'js',
          intro: 'Fail-open authorization: an error in the security check is swallowed and treated as "allow".',
          vuln: `// FAIL OPEN: the catch treats "couldn't check" as "allow" → anyone is admin when authz blips
try { allowed = permissionCheck(userId); }
catch (err) { allowed = true; }
if (!allowed) return res.status(403).json({ error: 'forbidden' });
res.json({ allowed: true, action: 'performed' });`,
          safe: `// FAIL CLOSED: if we can't confirm you're allowed, the answer is "no"
// 503, because this is our outage, not the caller's fault — they can retry
try { allowed = permissionCheck(userId); }
catch (err) {
  console.warn(JSON.stringify({ event: 'authz.unavailable', reason: err.message }));
  return res.status(503).json({ error: 'authorization service unavailable' });
}
if (!allowed) return res.status(403).json({ error: 'forbidden' });`,
        },
        expect: {
          vuln: 'service down → allowed:true (fail open); anyone is admin',
          safe: 'service down → 503 (fail closed); up + non-admin → 403',
        },
      },
      {
        id: 'report',
        title: 'Ask for a report (leak the stack)',
        description: 'Request a table by name. The vuln side interpolates it into SQL and, on any error, returns err.message AND err.stack. The safe side allow-lists tables and returns an opaque reference with no internals.',
        method: 'GET', path: '/report',
        inputs: [{ name: 'table', label: 'table', default: 'sqlite_master', in: 'query', options: ['sqlite_master', 'nope', 'invoices', 'accounts'] }],
        hint: 'Try "sqlite_master" or "nope" to trigger the error path; "invoices"/"accounts" are the allow-listed tables.',
        code: {
          lang: 'js',
          intro: 'Stack-trace leakage (CWE-209): an exception becomes schema / paths / versions for the attacker.',
          vuln: `// on any error, hand the client err.message AND err.stack — a reconnaissance gift
try {
  const rows = db.prepare(\`SELECT * FROM \${table}\`).all();   // identifier interpolation, too
  res.json({ rows });
} catch (err) {
  res.status(500).json({ error: err.message, stack: err.stack });
}`,
          safe: `// allow-list the table; on error return an opaque reference and log the detail server-side
const REPORTABLE_TABLES = new Set(['invoices', 'accounts']);
if (!REPORTABLE_TABLES.has(table))
  return res.status(400).json({ error: 'unknown report', reference: crypto.randomUUID() });
// ... on a genuine error: log { reference, detail } server-side, return only { error, reference }`,
        },
        expect: {
          vuln: 'dumps rows for any table, or a full stack trace on error',
          safe: '400 opaque {error, reference} for anything off the allow-list',
        },
      },
      {
        id: 'transfer',
        title: 'Transfer money that fails midway',
        description: 'Move funds with a downstream failure injected after the debit. The vuln side has no transaction: it debits, then dies, and the money is gone. The safe side wraps both writes in one transaction that rolls back. Check /balances before and after.',
        method: 'POST', path: '/transfer', query: { failMidway: '{failMidway}' },
        inputs: [
          { name: 'fromUserId', label: 'fromUserId', default: '1', in: 'body' },
          { name: 'toUserId', label: 'toUserId', default: '2', in: 'body' },
          { name: 'amountCents', label: 'amountCents', default: '5000', in: 'body' },
          { name: 'failMidway', label: 'failMidway', default: '1', options: ['1', '0'] },
        ],
        code: {
          lang: 'js',
          intro: 'Non-atomic writes: a multi-step operation that throws halfway leaves money half-moved.',
          vuln: `// two writes, NO transaction: debit first, then die — the money simply vanishes
db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?').run(amount, fromUserId);
if (failMidway) return res.status(500).json({ error: 'downstream failure after debit' });
db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, toUserId);`,
          safe: `// ONE transaction: any throw rolls back every write inside it, so balances are conserved
const doTransfer = db.transaction(() => {
  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE user_id = ?').run(amount, fromUserId);
  if (failMidway) throw new Error('downstream failure after debit');   // unwinds the debit too
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amount, toUserId);
});
try { doTransfer(); res.json({ ok: true }); }
catch (err) { res.status(409).json({ error: 'transfer failed and was rolled back' }); }`,
        },
        expect: {
          vuln: '500, and the debited amount vanishes — system total drops',
          safe: '409 rolled back — every balance and the total are conserved',
        },
      },
      {
        id: 'balances',
        title: 'Check balances (system total)',
        description: 'Ground truth: every account balance and the system total. Run it before and after a failed transfer — in a correct system the total is CONSERVED no matter what.',
        method: 'GET', path: '/balances',
        code: {
          lang: 'js',
          intro: 'Not a vuln itself — the yardstick. The system total should never change just because a transfer failed.',
          vulnLabel: '📊 Ground truth — the invariant to watch',
          vuln: `// every account balance + the system total. In a correct system the total is
// CONSERVED across any transfer — run this before and after a failed transfer.
const accounts = db.prepare('SELECT user_id, balance_cents FROM accounts ORDER BY user_id').all();
const total = accounts.reduce((sum, a) => sum + a.balance_cents, 0);
res.json({ accounts, total });`,
        },
        expect: {
          vuln: 'total shrinks after a failed transfer (money lost)',
          safe: 'total unchanged — the rollback preserved the invariant',
        },
      },
    ],
  },
};
