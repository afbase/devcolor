# A01:2025 — Broken Access Control

> #1 on the list, unchanged from 2021. On average, one or more of this
> category's 40 CWEs was found in a large share of every application tested.
> SSRF (CWE-918) was folded into this category for 2025.

**The one-sentence version:** access control is *enforcing* that users can only
do what they're allowed to. It breaks when the check is missing, done in the
wrong place (the browser), or trusts a value the user controls.

Source files: [`app/routes/a01-broken-access-control.js`](../../app/routes/a01-broken-access-control.js)
· Tests: [`tests/a01.test.js`](../../tests/a01.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) IDOR — Alice reads Carol's confidential invoice just by changing the id.
curl "http://localhost:3000/vuln/a01/invoices/1004?as=alice"

# 2) Forced browsing — the admin user list has no lock on it at all.
curl "http://localhost:3000/vuln/a01/admin/users?as=bob"

# 3) Client-side-only control — the UI hides the button; curl doesn't care.
curl -X POST "http://localhost:3000/vuln/a01/invoices/purge?as=bob"
```

Or run all three at once: `bash scripts/exploit-a01.sh`.

## Read it

Open the route file and compare the `vuln` router to the `safe` router. The
whole of bug #1 is a missing `AND user_id = ?` in one SQL query.

## Fix it (the ideas, so you can spot them elsewhere)

- **Deny by default.** The safe router rejects anything with no identity.
- **Enforce ownership in the query**, so there's no code path that forgets it.
- **Check the role on the server**, regardless of what the UI shows.
- **Reuse one access-control mechanism** (`requireRole`) instead of re-writing
  the check per endpoint.
- **Return 404, not 403**, for records you may not see — a 403 confirms the id
  exists and leaks the id space.

## Prove it

```bash
npm run test:a01
```

## Spot it in review

- An id, filename, or key that comes from the request and is used to fetch a
  record **without** a matching ownership/tenant filter.
- Authorization logic that lives only in front-end code.
- `if (user.isAdmin)` in the template but not in the handler.

## Read more
<https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/>
