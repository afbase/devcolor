# Facilitator guide — the OWASP Top 10:2025 in an hour

Audience: working engineers, roughly junior. Goal: they leave able to *recognise*
all ten categories and to *break, understand, and fix* four of them hands-on.

You can't do ten categories justice in sixty minutes, so don't try. Deep-dive
four with live labs; survey the other six. Everyone gets the repo to finish the
rest on their own.

## Before you start

- Ask everyone to run `npm install && npm run doctor && npm start` *before* the
  session (put it on the calendar invite). Have one working laptop on the
  projector.
- Open `http://localhost:3000` — the index links every `/vuln` and `/safe`
  route.

## Run of show (60 min)

| Time | Segment | Notes |
|------|---------|-------|
| 0:00–0:05 | **Intro + how to think about this** | The list is data-informed (2.8M apps, ~175k CVEs) plus a community survey for what data can't see yet. Frame every category as *untrusted input crossing a trust boundary*. |
| 0:05–0:13 | **A01 Broken Access Control** (lab) | Live-run `scripts/exploit-a01.sh`. The whole IDOR bug is a missing `AND user_id = ?`. Land "deny by default" and "404 not 403". |
| 0:13–0:21 | **A05 Injection** (lab) | `scripts/exploit-a05.sh`. Show `admin'--` logging in, then the parameterised fix. Mention XSS lives here too. |
| 0:21–0:29 | **A02 Security Misconfiguration** (lab) | The biggest mover. Browse `/vuln/a02/files/` to the leaked `.env.backup`; show the stack-trace `/boom`; diff the cookie/headers. |
| 0:29–0:37 | **A03 Supply Chain Failures** (lab) | New + survey #1. `curl /vuln/a03/inventory` (2 declared, dozens installed), then `npm audit`, `npm ci` vs `npm install`, SHA-pinned Actions. |
| 0:37–0:55 | **Rapid survey: A04, A06, A07, A08, A09, A10** | ~3 min each. One demo line + the fix idea. A10 is new — spend the extra minute on "fail closed". |
| 0:55–1:00 | **What to do Monday** | Point at the "spot it in review" checklists. Pick one: turn on a linter rule, add a breached-password check, commit a lockfile + `npm ci`. |

## The one message per category (if you only say one thing)

- **A01** — check authorization on the server, scoped to the caller, every time.
- **A02** — ship a hardened config; don't leak files, errors, or headers.
- **A03** — you run code you didn't write; pin it, inventory it, audit it.
- **A04** — CSPRNG for randomness, slow salted hash for passwords, AEAD for encryption.
- **A05** — keep data out of the code channel (parameterise, no shell, encode output).
- **A06** — threat-model the design; some bugs can't be patched in later.
- **A07** — MFA, no defaults, rate-limit, rotate sessions, block breached passwords.
- **A08** — verify signatures; don't trust-merge or deserialize untrusted data.
- **A09** — log the security events *and alert* on them; redact secrets.
- **A10** — fail closed, roll back, and never hand the stack trace to the user.

## If a demo misbehaves

- `POST /reset` reseeds the database without a restart.
- Every exploit is also a test — `npm run test:aNN` proves the point even if a
  live curl gets fumbled on stage.

## Tips

- Type the exploits live; the "aha" is watching `admin'--` actually work.
- After each break, open the route file and scroll from `VULNERABLE` to
  `SECURE`. The comments are written to be read aloud.
- Resist finishing every category. The repo is the homework.
