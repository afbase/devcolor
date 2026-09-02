# A02:2025 — Security Misconfiguration

> ▲ #5 → #2, the biggest mover on the list. The 2025 data found *some*
> misconfiguration in effectively every application tested. None of it is
> clever: it's the insecure default nobody flipped.

**The one-sentence version:** the code can be perfect and you can still be owned
by a verbose header, a listable directory, a debug endpoint left on, a stack
trace mailed to the attacker, or a cookie with no flags.

Source files: [`app/routes/a02-security-misconfiguration.js`](../../app/routes/a02-security-misconfiguration.js)
· Tests: [`tests/a02.test.js`](../../tests/a02.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) Fingerprinting — the response advertises the framework and server version.
curl -sI "http://localhost:3000/vuln/a02/login-demo" | grep -Ei 'x-powered-by|server'

# 2) Directory listing leaks a forgotten backup of the production .env.
curl -s "http://localhost:3000/vuln/a02/files/"
curl -s "http://localhost:3000/vuln/a02/files/.env.backup"   # STRIPE_KEY, DATABASE_URL…

# 3) A debug endpoint dumps the entire process environment.
curl -s "http://localhost:3000/vuln/a02/debug"

# 4) The error handler returns the stack trace (paths, versions, the DB error).
curl -s "http://localhost:3000/vuln/a02/boom"

# 5) The session cookie ships with no HttpOnly / Secure / SameSite.
curl -sI "http://localhost:3000/vuln/a02/login-demo" | grep -i set-cookie
```

Now diff each against the `/safe/a02/...` version.

## Read it

Open the route file and compare the `vuln` and `safe` routers. Every fix is a
default being flipped, not new logic:
- `dotfiles: 'allow'` + a listing handler → `dotfiles: 'ignore'`, no listing.
- a `/debug` route that always exists → one mounted only behind an env flag.
- `res.send(err.stack)` → log the detail, return an opaque reference id.
- a hand-written `Set-Cookie` → `res.cookie(..., {httpOnly, secure, sameSite})`.

## Fix it (the ideas, so you can spot them elsewhere)

- **Strip fingerprints** (`X-Powered-By`, `Server`) and set the baseline
  security headers — CSP, HSTS, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `X-Frame-Options`. In production, use `helmet`.
- **Don't serve secrets from a web root**, and turn directory listing off.
- **Make debug/admin surfaces opt-in**, so the default state is off.
- **Return an opaque error to the client, log the detail server-side.** The
  reference id is enough for a support ticket and useless to an attacker.
- **Set every cookie flag** on every session cookie.

## Prove it

```bash
npm run test:a02
```

## Spot it in review

- `express.static` on a directory that also contains config or backups.
- A `Set-Cookie` written by hand, or `res.cookie` with no options object.
- `res.send(err)` / `res.json({ stack: err.stack })` in an error handler.
- Any `/debug`, `/status`, `/env` route with no auth and no feature flag.
- A missing security-headers middleware (or `helmet`) at the app root.

## Read more
<https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/>
