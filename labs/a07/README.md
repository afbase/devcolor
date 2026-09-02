# A07:2025 — Authentication Failures

> #7, renamed from "Identification and Authentication Failures". Most of this
> category is **not** the password comparison — it's everything around it:
> rate limiting, MFA, session handling, default credentials, and reusing
> breached passwords.

Source: [`app/routes/a07-authentication-failures.js`](../../app/routes/a07-authentication-failures.js)
· Sessions: [`app/lib/sessions.js`](../../app/lib/sessions.js)
· Tests: [`tests/a07.test.js`](../../tests/a07.test.js)

## Break it

```bash
# Password spraying — no throttle, no MFA, and the default admin/admin lives.
node scripts/credential-stuffing.js admin

# Username oracle — the error tells you whether the account exists.
curl -s "http://localhost:3000/vuln/a07/login" -H 'content-type: application/json' -d '{"username":"alice","password":"x"}'
curl -s "http://localhost:3000/vuln/a07/login" -H 'content-type: application/json' -d '{"username":"nope","password":"x"}'

# Session fixation — the id the attacker planted survives login.
curl -s "http://localhost:3000/vuln/a07/login" -H 'content-type: application/json' \
  -H 'cookie: sid=sess-attacker-controlled' -d '{"username":"dana","password":"trombone-glacier-42-mango"}'
```

## Read it

Open the route file and compare `vuln` to `safe`. The vuln login even verifies
the password "correctly" — and is still broken five ways: md5 instead of scrypt,
no throttle, distinct errors that leak which accounts exist, the honoured
default `admin/admin`, and a reused (attacker-planted) session id. The safe login
closes each in turn. Note the key insight in the code comments: **rate limiting
does not save you from `admin/admin`** — only refusing breached passwords does,
so a correct-but-breached login returns `403 {mustResetPassword:true}`, not a
session. The two controls defend against different things and you need both.

## Fix it

- **MFA** — OWASP's first prevention bullet for this category.
- **No default credentials.** A correct-but-breached password is blocked at
  login and must be rotated (rate limiting doesn't save you from `admin/admin`;
  removing it does — the two controls defend against different things).
- **Rate limit / lock out** repeated failures (per-account *and* per-IP).
- **One identical error** for every failure mode.
- **Rotate the session id at every privilege change**; invalidate server-side
  on logout; use high-entropy ids.
- **Check new passwords against a breach corpus**; prefer length over
  composition rules.

## Prove it
```bash
npm run test:a07
```

## Spot it in review
- A login with no rate limiting.
- Different responses for "no such user" vs "wrong password".
- A session id that isn't regenerated after login.
- Composition rules (`1 upper, 1 digit…`) as the only password policy.

## Read more
<https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/>
