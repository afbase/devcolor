'use strict';
// A06:2025 — Insecure Design. Flaws in the PLAN, not the code: money flows that
// were never given the rule that makes them safe. Persona: a growth-obsessed
// VP who ships "delightful" checkout/refund/recovery flows and threat-models
// nothing. The profile page IS the live target — actions hit /vuln/a06 & /safe/a06.
module.exports = {
  persona: {
    name: 'Cash Flowers',
    title: 'VP of Growth Design at Refundr',
    company: 'Refundr',
    avatar: 'CF',
    color: '#e76f51',
    banner: 'linear-gradient(120deg,#264653,#e76f51 60%,#f4a261)',
    location: 'Austin, TX',
    connections: '6,540',
  },
  post: {
    time: '5h',
    reactions: 271, comments: 63, reposts: 29,
    headline: 'Refundr: friction is the only real bug',
    cta: 'Every flow is valid on its own — trust me',
    summary: `Flaws that live in the plan, not in a single buggy line — a checkout, refund, or account-recovery flow that runs exactly as designed, but the design never wrote down the invariant (one coupon per order, never refund more than was charged) that would have made it safe.`,
  },
  profile: {
    headline: 'VP Growth Design @ Refundr · "each step is valid, the sequence is the exploit"',
    about: `Insecure design is a flaw in the plan, not a typo in the code — a flow that behaves exactly as it was built to, because no one ever wrote down the rule that would have made it safe. A checkout, refund, or recovery flow can pass every code review and still be exploitable if it never accounts for a user acting in bad faith.

That's what makes this category different: there's no single line to patch, because the code isn't technically wrong — the missing invariant was never part of the design in the first place.

Try it below: stack coupons until the order is free, refund an invoice for more than it ever cost, or recover an account using a "secret" that anyone could guess.`,
    highlights: ['Coupon stacking', 'Missing refund invariant', 'Refund > charge', 'Knowledge-based recovery', 'Account enumeration oracle'],
  },
  bench: {
    intro: 'Refundr’s money flows. The code has no ordinary bug — the DESIGN is missing a rule. Run vuln vs safe and watch where the safe side finally states the invariant.',
    actions: [
      {
        id: 'refund-overpay',
        title: 'Refund more than was ever charged',
        description: 'The vuln refund ties the payout to nothing — no invoice, no cap — so it just adds whatever you ask to the account balance. The safe refund must reference an invoice you OWN and can never exceed what it charged.',
        method: 'POST', path: '/refund', bodyType: 'json',
        body: { userId: '{userId}', invoiceId: '{invoiceId}', amountCents: '{amountCents}' },
        inputs: [
          { name: 'userId', label: 'User ID', default: '1', options: ['1', '2', '3', '5'] },
          { name: 'invoiceId', label: 'Invoice ID (safe side checks ownership)', default: '1001' },
          { name: 'amountCents', label: 'Refund amount (cents)', default: '500000', size: 200 },
        ],
        hint: 'Invoice 1001 is Alice’s $42.00 laptop stand. Refunding $5,000 against it is absurd — the safe side says so.',
        code: {
          lang: 'js',
          intro: 'Insecure design: the rule "never refund more than was charged" was never stated.',
          vuln: `// nothing ties the payout to a real charge — refunding more than was paid just adds balance
const amount = Number(req.body.amountCents) || 0;
db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE user_id = ?')
  .run(amount, userId);`,
          safe: `// the invariant lives next to the operation: must reference an invoice you OWN,
// and can never exceed what it charged
const invoice = db.prepare('SELECT id, user_id, amount_cents FROM invoices WHERE id = ? AND user_id = ?')
  .get(invoiceId, userId);
if (!invoice) return res.status(404).json({ error: 'no such invoice' });
if (amount <= 0 || amount > invoice.amount_cents)
  return res.status(400).json({ error: 'refund exceeds the invoice amount' });`,
        },
        expect: { vuln: 'balance jumps by the full amount, no invoice needed', safe: 'HTTP 400 — refund exceeds the invoice amount' },
      },
      {
        id: 'recover-oracle',
        title: 'Recover an account by guessing a maiden name',
        description: 'Knowledge-based recovery: a "security question" is public info. Guess "smith" and the vuln hands you a reset token. The safe side never branches on whether you were right — same response every time, no in-band token, no enumeration oracle.',
        method: 'POST', path: '/recover', bodyType: 'json',
        body: { motherMaidenName: '{motherMaidenName}' },
        inputs: [
          { name: 'motherMaidenName', label: "Mother's maiden name", default: 'smith', size: 220 },
        ],
        hint: 'Try "smith" then "jones": vuln flips between a token and a 401 (an oracle). Safe returns the identical message either way.',
        code: {
          lang: 'js',
          intro: 'A guessable "secret" plus a branching response is an account-enumeration oracle.',
          vuln: `// knowledge-based recovery + an enumeration oracle: right answer → token, wrong → 401
const maiden = String(req.body.motherMaidenName || '').toLowerCase();
if (maiden === 'smith') {
  const token = crypto.randomBytes(16).toString('hex');
  return res.json({ ok: true, resetToken: token });   // in-band token, too
}
res.status(401).json({ ok: false, error: 'wrong answer' });`,
          safe: `// identical response whether or not the account exists; no in-band token, no "security question"
// (a real app emails a single-use expiring token to the address on file)
res.json({ ok: true, message: 'If that account exists, we have sent reset instructions.' });`,
        },
        expect: { vuln: '"smith" → a live resetToken; wrong answer → 401 (an oracle)', safe: 'always "If that account exists, we have sent reset instructions."' },
      },
      {
        id: 'checkout-stack',
        title: 'Stack coupons toward a free order',
        description: 'The design said "WELCOME10 is 10% off" but never "one coupon per order." The vuln sums every coupon in the array, uncapped and unconsumed; the safe side rejects >1 coupon and consumes the coupon atomically so it can’t be reused.',
        method: 'POST', path: '/checkout',
        // /checkout expects `coupons` as a JSON ARRAY. The `json:true` input
        // carries a real array, so the stacking exploit is fully clickable —
        // edit the list and watch the total collapse on /vuln.
        rawBody: '{"priceCents": {priceCents}, "coupons": {coupons}}',
        inputs: [
          { name: 'priceCents', label: 'Price (cents)', default: '10000' },
          { name: 'coupons', label: 'Coupons (JSON array)', json: true, size: 320,
            default: '["WELCOME10","LOYAL25","LOYAL25","LOYAL25"]' },
        ],
        hint: 'Stack as many as you like on /vuln. The safe route 400s on >1 coupon.',
        code: {
          lang: 'js',
          intro: 'Each coupon use is valid; the sequence is the exploit. The missing rule is the bug.',
          vuln: `// no "one coupon per order" rule: every code in the array is summed, uncapped, unconsumed
let percent = 0;
for (const code of codes) {
  const c = db.prepare('SELECT percent_off FROM coupons WHERE code = ?').get(code);
  if (c) percent += c.percent_off;
}`,
          safe: `// state the rule; consume the coupon ATOMICALLY so it can't be reused or raced
if (codes.length > 1) return res.status(400).json({ error: 'at most one coupon per order' });
const consumed = db.prepare(
  'UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses'
).run(code);
if (consumed.changes === 0) return res.status(400).json({ error: 'coupon has already been used' });`,
        },
        expect: { vuln: 'sums every coupon in the array — order trends to free (try the default: 85% off)', safe: 'HTTP 400 "at most one coupon per order"; each coupon consumed once' },
      },
    ],
  },
};
