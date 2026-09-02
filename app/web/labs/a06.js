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
    text: `At Refundr we believe security reviews kill velocity 🏎️ Every line of our checkout, refund, and account-recovery code does EXACTLY what it was designed to do.

Highlights this quarter: stack as many coupons as your heart desires 🎟️, self-serve refunds with zero paperwork 💸, and instant password recovery — just tell us your mother's maiden name.

No threat model, no invariants, no "but what if a user does that on purpose." Delight first!

#growth #frictionless #designthinking #fintech #security`,
  },
  profile: {
    headline: 'VP Growth Design @ Refundr · "each step is valid, the sequence is the exploit"',
    about: `I design flows, not defenses. Nobody ever wrote down the rule "one coupon per order" or "never refund more than you charged," so those rules don't exist here.

Poke at my money below. Stack coupons until the order is free. Refund an invoice for more than it ever cost and watch the balance climb. Recover an account with a maiden name anyone could guess. The code is "correct" — the design is the wound.`,
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
        expect: { vuln: 'sums every coupon in the array — order trends to free (try the default: 85% off)', safe: 'HTTP 400 "at most one coupon per order"; each coupon consumed once' },
      },
    ],
  },
};
