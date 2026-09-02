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
    text: `Real talk about resilience 🧵 At FailOpen we have a simple rule: when a security check errors out, just let the request through. Availability > paranoia! If our authz service blips, everyone gets to be admin for a bit. No biggie. 🤷

Bonus: our error responses include the full stack trace so users can "self-serve debug." And our money transfers? Two writes, no transaction — if step two fails we simply... don't put the money back. It builds character. 💸

#resilience #errorhandling #failopen #movefast #whatcouldgowrong`,
  },
  profile: {
    headline: 'Principal Engineer, Error Handling @ FailOpen · catch { allow: true }',
    about: `My catch blocks are optimists. When my authz service goes down, I assume you're allowed. When a query throws, I hand you err.message and err.stack. When a money transfer dies halfway, I keep the debit and skip the credit.

Break me below. Knock the authz service offline, then perform an admin action as a nobody and watch /vuln wave you through while /safe fails closed with a 503. Throw a bad table name at my report and read my stack trace. Or run a transfer that fails midway and check /balances — on /vuln the money just vanishes; on /safe the whole thing rolls back and the total is conserved.`,
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
        expect: {
          vuln: 'total shrinks after a failed transfer (money lost)',
          safe: 'total unchanged — the rollback preserved the invariant',
        },
      },
    ],
  },
};
