# A06:2025 — Insecure Design

> #4 in 2021, now #6 (the industry has improved at threat modelling). This is
> about **missing or ineffective control *design*** — flaws you can't patch
> because the code does exactly what it was designed to do.

**The one-sentence version:** the bug is in the plan, not the code — you find
these by thinking like an attacker before you build, not by running a linter.

Source: [`app/routes/a06-insecure-design.js`](../../app/routes/a06-insecure-design.js)
· Tests: [`tests/a06.test.js`](../../tests/a06.test.js)

## Break it

```bash
# Business-logic flaw: stack a "one per order" coupon ten times. Each use is
# individually valid; the sequence is the abuse.
curl "http://localhost:3000/vuln/a06/checkout" -H 'content-type: application/json' \
  -d '{"priceCents":10000,"coupons":["WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10","WELCOME10"]}'

# No invariant: refund more than was ever paid, and the balance goes up.
curl "http://localhost:3000/vuln/a06/refund" -H 'content-type: application/json' \
  -d '{"userId":1,"amountCents":5000000}'

# Knowledge-based recovery: guessing a common surname yields a reset token.
curl "http://localhost:3000/vuln/a06/recover" -H 'content-type: application/json' \
  -d '{"username":"carol","motherMaidenName":"Smith"}'
```

## Read it

Open the route file and compare `vuln` to `safe`. There is no "bug" to point at
in the usual sense — each vuln handler does exactly what it was told to do. The
flaw is the *missing rule*: the vuln `checkout` was never told "one coupon, and
consume it"; the vuln `refund` was never told "never exceed the invoice"; the
vuln `recover` treats a public fact as a secret. The safe side adds the rule and
enforces it at the operation — atomically, so there's no check-then-act race.

## Fix it

- **State the rule, then enforce it server-side** (one coupon per order; the
  coupon's own `max_uses` consumed atomically).
- **Put invariants next to the operation** ("never refund more than was paid").
- **Threat-model the critical flows** — auth, access control, payments — and
  write the abuse cases into the user stories.
- **Recovery through a channel the user controls**, with single-use expiring
  tokens; don't leak which accounts exist.

## Prove it
```bash
npm run test:a06
```

## Spot it in review
- A limit enforced in the UI but not the API.
- Money/quantity operations with no upper bound or invariant.
- "Security questions" for account recovery.
- Features shipped with no discussion of how they could be abused at scale.

## Read more
<https://owasp.org/Top10/2025/A06_2025-Insecure_Design/>
