# A10:2025 — Mishandling of Exceptional Conditions

> **Brand new for 2025.** The list's newest entry is about what your code does
> when something goes *wrong*: swallowing errors in a security check (failing
> open), leaking internals through error messages, and leaving multi-step
> operations half-done when they throw.

**The one-sentence version:** the exception path is a code path — and it's the
one attackers aim for, because it's the one nobody tested.

Source files: [`app/routes/a10-exceptional-conditions.js`](../../app/routes/a10-exceptional-conditions.js)
· Tests: [`tests/a10.test.js`](../../tests/a10.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) Fail OPEN — take the internal authz service "down" so the check throws,
#    then watch a non-admin walk into an admin action.
curl -s -X POST "http://localhost:3000/vuln/a10/authz-service/down"
curl -s -X POST "http://localhost:3000/vuln/a10/admin-action" \
  -H 'content-type: application/json' -d '{"userId":2}'
# → { "allowed": true, ... }   ← the catch treated "couldn't check" as "yes"
curl -s -X POST "http://localhost:3000/vuln/a10/authz-service/up"   # reset

# 2) Leaked internals — an error hands you the message AND the full stack trace.
curl -s "http://localhost:3000/vuln/a10/report?table=does_not_exist"
# → { "error": "no such table: does_not_exist", "stack": "Error: ... /app/..." }

# 3) No atomicity — fail a transfer halfway and the money simply vanishes.
curl -s "http://localhost:3000/vuln/a10/balances"
curl -s -X POST "http://localhost:3000/vuln/a10/transfer?failMidway=1" \
  -H 'content-type: application/json' \
  -d '{"fromUserId":1,"toUserId":2,"amountCents":10000}'
curl -s "http://localhost:3000/vuln/a10/balances"   # → alice debited, bob NOT credited, total dropped
```

Run each against `/safe/a10/...`: the authz outage returns **503** (fail
closed), the report returns a **reference with no stack**, and the failed
transfer **rolls back** so the total is conserved.

## Read it

Open the route file and compare the two routers.

- Vuln `/admin-action`: `try { allowed = check() } catch { allowed = true }`.
  The one line `allowed = true` in the catch is the whole vulnerability.
- Vuln `/report`: returns `err.message` **and** `err.stack` to the client.
- Vuln `/transfer`: two separate `UPDATE`s with no transaction — a throw between
  them leaves the debit committed and the credit never made.

## Fix it (the ideas, so you can spot them elsewhere)

- **Fail closed.** If a security check can't complete, deny — the safe
  `/admin-action` returns **503** on a thrown check, never "allow".
- **Return opaque errors.** The safe `/report` allow-lists table names and, on
  any failure, returns a random **reference** (logged server-side) and no stack.
- **Make multi-step writes atomic.** The safe `/transfer` runs one
  `db.transaction()`; guarding `balance >= amount` and letting any throw roll
  back every write inside it means money is never half-moved.

## Prove it

```bash
npm run test:a10
```

The tests show: with authz down, vuln `admin-action` returns `allowed:true`
(200) while safe returns 503; safe allows the admin (userId 4) and denies
others (403); vuln `/report` leaks the stack while safe returns a reference and
rejects unknown tables (400); and the vuln transfer loses money while the safe
transfer rolls back — with the happy path moving money exactly once.

## Spot it in review

- A `catch` block that sets an allow/authenticated/valid flag to `true`, or
  swallows the error and continues as if it succeeded.
- `res.json({ error: err })`, `err.stack`, or `err.message` sent to clients.
- Two or more related writes (debit/credit, insert/update) **not** wrapped in a
  single transaction.
- "This should never happen" comments guarding no actual handling.

## Read more

<https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/>
