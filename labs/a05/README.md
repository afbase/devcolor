# A05:2025 — Injection

> #3 in 2021, now #5 — still one of the most-tested categories, with the most
> CVEs. **Cross-Site Scripting (XSS) lives here** (30,000+ CVEs on its own),
> described as high-frequency/low-impact, alongside SQL and command injection.

**The one-sentence version:** untrusted input reaches an interpreter (SQL, the
shell, HTML, an ORM) as *code* instead of *data*.

Source: [`app/routes/a05-injection.js`](../../app/routes/a05-injection.js)
· Tests: [`tests/a05.test.js`](../../tests/a05.test.js)

This lab has four interpreters, each a vuln/safe pair at the **same path** so
you can diff them with `curl`:

| Path | Interpreter | Attack |
|------|-------------|--------|
| `POST /login` | SQL | authentication bypass with a comment |
| `GET /search` | SQL | UNION-based data exfiltration |
| `GET /ping`   | OS shell | command chaining with `;` |
| `GET /echo`   | HTML | **reflected** XSS |
| `GET/POST /guestbook` | HTML | **stored** XSS |

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) SQLi login — log in as admin with a comment payload, no password.
curl "http://localhost:3000/vuln/a05/login" \
  --data-urlencode "username=admin'--" --data-urlencode "password=anything"

# 2) SQLi search — UNION-based extraction of every username + password hash.
curl -G "http://localhost:3000/vuln/a05/search" \
  --data-urlencode "q=x' UNION SELECT id, username, password_md5, 0 FROM users--"

# 3) OS command injection — a semicolon runs a second command.
curl -G "http://localhost:3000/vuln/a05/ping" --data-urlencode "host=localhost;echo INJECTED"

# 4a) Reflected XSS — open this in a browser, not curl:
#     http://localhost:3000/vuln/a05/echo?q=<script>alert(document.cookie)</script>

# 4b) Stored XSS — post the payload ONCE...
curl "http://localhost:3000/vuln/a05/guestbook" \
  --data-urlencode "author=mallory" --data-urlencode "body=<script>alert(1)</script>"
# ...then load the wall. The <script> is live for every later visitor:
curl "http://localhost:3000/vuln/a05/guestbook"
```

Or: `bash scripts/exploit-a05.sh`.

### Why stored XSS is the dangerous one

Reflected XSS needs the victim to click your crafted link. **Stored** XSS is
saved server-side and runs for *everyone who later views the page* — no link
required. In this app the guestbook renders to every visitor, and the support
tickets table is read by the **support agent inside an admin console**. A
`<script>` in a ticket body therefore executes with the agent's session — a
customer's input crosses a privilege boundary and can hijack an admin. That
cross-user reach is exactly why XSS still matters even though any single
payload is "low impact".

## Read it

Open the route file and compare `vuln` to `safe`. The fix is the same idea four
times: **keep untrusted input in the data channel, never the code channel.**
Note that the stored-XSS fix encodes on **output** (`renderGuestbook` with
`escapeHtml`), not on input — the same stored value may be shown in several
different contexts, and each needs its own encoding.

## Fix it

- **Parameterised queries** (`?` placeholders). The single highest-value habit
  in this workshop — the driver never re-parses a bound value as SQL.
- **No shell**: `execFile('ping', ['-c','1', host])` instead of `exec()` with a
  string — plus positive (allow-list) input validation on the hostname.
- **Output encoding for the context** you're writing into (`escapeHtml` for an
  HTML text node) — the fix for XSS.
- **A Content-Security-Policy** as defence-in-depth: even if an encoding bug
  slips through, `script-src 'self'` refuses the injected inline script.

## Prove it

```bash
npm run test:a05
```

## Spot it in review

- A SQL/HQL string built with `+`, template literals, or `.format()`.
- `exec()`, `system()`, `eval()` with anything derived from a request.
- User input written into HTML without encoding — **especially** stored input
  that is later rendered to a *different* user (comments, tickets, profiles).
- "We validate on the client" as the only defence.

## Read more
<https://owasp.org/Top10/2025/A05_2025-Injection/>
