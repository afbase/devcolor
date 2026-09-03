# Companion deck — content outline (≤24 slides)

Audience: engineers **new to information security**. Plain language, no jargon
without a definition. Four categories get depth (**A01, A05, A02, A03**); the
rest are a quick tour. Diagrams live in `docs/diagrams/*.png`; live-demo
commands assume `docker compose up` and the feed at `http://localhost:3000`.

> This is the *content*. Once the buildsheet Doc is shared with the connected
> Google account (or the template is pasted here), each slide below maps 1:1
> into your template's fields.

---

### 1 — Title
- **OWASP Top 10 : 2025 — break it, fix it, prove it.** A hands-on hour.
- Speaker: "You don't need a security background. We'll attack a fake app, then fix it."

### 2 — What you'll actually do
- Every vulnerability: **see it break → understand why → fix it → prove the fix with a test.**
- You'll run real commands against a deliberately broken app on your own laptop.

### 3 — What is the "OWASP Top 10"?
- A free, community list of the **ten most common ways web apps get broken**, refreshed every few years. 2025 is the newest.
- Not a compliance checklist — a "where bugs actually happen" ranking.

### 4 — One idea that explains all ten
- **Untrusted input crossing a trust boundary.** Data from "out there" reaches somewhere that trusts it.
- Keep this in mind for every category.

### 5 — Our playground (setup)  · visual: `architecture.png`
- A LinkedIn-style feed: each **post = a company that shipped a bug**; each **profile = a live target** you attack.
- `docker compose up` → feed `:3000`, Grafana `:3001`, Prometheus `:9090`.
- The profile shows the exact **`curl` commands** to run by hand (buttons are optional).

---
## A01 — Broken Access Control  (#1)
### 6 — What it is (plain language)
- **Seeing or doing things that aren't yours.** The app forgets to check "are you allowed?"
- The most common serious flaw on the web.

### 7 — Demo: IDOR  · visual: `a01-idor.png`
- Live: `curl -s 'http://localhost:3000/vuln/a01/invoices/1004?as=alice'`
- Alice reads **Carol's confidential invoice** just by changing the number.
- Fixed side returns `404` — the query is scoped to *you*.

### 8 — Demo: SSRF (new to A01 in 2025)  · visual: `a01-ssrf.png`
- A "preview this link" feature makes the **server** fetch a URL you give it.
- Live: `curl -s 'http://localhost:3000/vuln/a01/unfurl?url=http://internal-api:8081/internal/admin/flag&as=alice'`
- The server reaches an **internal-only** service and hands you its secrets.

### 9 — The fix + spot it in review
- Deny by default; **check ownership in the query**; check the role on the server (not just hide a button); for SSRF, block internal/loopback addresses.
- Red flag: an id/filename from the request used with no "is this yours?" check.

---
## A05 — Injection  (#5; includes XSS)
### 10 — What it is
- The app pastes your input into a command (a database query, a shell, a web page). Your input becomes **code**, not data.

### 11 — Demo: SQL injection  · visual: `a05-sqli.png`
- Live: log in with username `admin'--` and any password → **you're admin**.
- The `--` turns the password check into a comment.

### 12 — Demo: stored XSS (cross-site scripting)
- Live: post `<script>...</script>` to the guestbook; every later visitor's browser runs it.
- Plant: `curl -s localhost:3000/vuln/a05/guestbook -H 'content-type: application/json' -d '{"author":"m","body":"<script>alert(1)</script>"}'` then open the page.

### 13 — The fix + spot it in review
- **Parameterized queries** (data stays data); **encode output** for the page (kills XSS). No string-built SQL; no shell from user input.

---
## A02 — Security Misconfiguration  (▲ #5 → #2)
### 14 — What it is  · visual: `a02-misconfig.png`
- The **code is fine; the settings are not** — default accounts, directory listings, debug pages, leaked errors. The biggest mover in 2025.

### 15 — Demo + fix
- Live: `curl -s http://localhost:3000/vuln/a02/files/.env.backup` → a forgotten file leaks the **Stripe key and DB password**.
- Fix: turn off listings, hide dotfiles, hide error details, add security headers. (Fixed side: `404`.)
- Red flag: debug endpoints or stack traces reachable in production.

---
## A03 — Software Supply Chain Failures  (NEW · voted #1 concern)
### 16 — What it is  · visual: `a03-supplychain.png`
- You **run a lot of code you didn't write** — your libraries' libraries. Any one of them (or your build pipeline) can be compromised.

### 17 — Demo + fix
- Live: `curl -s http://localhost:3000/vuln/a03/inventory` → "we declared 3, installed dozens."
- Fix: commit a **lockfile** and use `npm ci`; generate an **SBOM**; run `npm audit`; pin CI actions to a commit. (SolarWinds, Log4Shell, the 2025 npm worm.)

---
## The rest, quickly
### 18 — Rapid tour (1 of 2)
- **A04 Cryptographic Failures** — weak/absent encryption, unsalted passwords → *use strong, salted hashing + TLS.*
- **A06 Insecure Design** — the flaw is in the plan (e.g. unlimited coupon stacking) → *threat-model before building.*
- **A07 Authentication Failures** — weak logins, default creds, no MFA → *MFA, rate-limit, block breached passwords.*

### 19 — Rapid tour (2 of 2)
- **A08 Integrity Failures** — trusting unsigned updates/data → *verify signatures.*
- **A09 Logging & Alerting Failures** — you can't see the attack → *log security events **and alert**.*
- **A10 Mishandling of Exceptional Conditions** (new) — failing "open" when something errors → *fail closed.*

### 20 — Seeing an attack happen (A09)
- Grafana dashboard: a brute-force run against the **fixed** login lights up a spike + alert; the same run on the **broken** login leaves it **flat**. That gap *is* A09.

### 21 — Proving the fix
- Every lab ships a test that **exploits the bug, then proves the fix holds** — **80/80 green**. Security you can run in CI.

### 22 — What to do Monday
- Pick one: turn on a security linter rule · commit a lockfile + `npm ci` · add a breached-password check · use each lab's "spot it in review" checklist.

### 23 — Recap
- One idea: untrusted input crossing a trust boundary. Four to remember: **access checks, safe queries, hardened config, your supply chain.**

### 24 — Go deeper
- The repo (all ten labs, curl-first profiles, Docker + Grafana) · `owasp.org/Top10/2025`.

---
## Notes on visuals
- **Mermaid diagrams**: rendered in `docs/diagrams/` — `architecture`, `a01-idor`,
  `a01-ssrf`, `a05-sqli`, `a02-misconfig`, `a03-supplychain` (PNG, drop straight in).
- **Terminal demos**: run the `curl` lines live for maximum effect. If you want
  static "terminal cards" (crisp images of the command + real output) or animated
  GIFs, say so and I'll generate them from the actual endpoints.
