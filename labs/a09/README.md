# A09:2025 — Security Logging & Alerting Failures

> #9 on the list. Renamed for 2025: "Monitoring" became **"Alerting"** — the
> point was never to *collect* logs, it was to **notice**. This category is the
> attacks you can't see, can't investigate, and are never paged about.

**The one-sentence version:** if a failed login, an injected log line, or a
leaked secret leaves no trace and trips no alert, the breach is already
invisible.

Source files: [`app/routes/a09-logging-alerting.js`](../../app/routes/a09-logging-alerting.js)
· Tests: [`tests/a09.test.js`](../../tests/a09.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) Silent failures — hammer the broken login and read the log. It's EMPTY.
for i in $(seq 1 50); do
  curl -s -o /dev/null -X POST "http://localhost:3000/vuln/a09/login" \
    -H 'content-type: application/json' -d '{"username":"alice","password":"wrong"}'
done
curl -s "http://localhost:3000/vuln/a09/logs"      # → nothing. 50 attacks, zero evidence.

# 2) Log injection — a newline forges a second, attacker-controlled log line.
curl -s -X POST "http://localhost:3000/vuln/a09/audit" \
  -H 'content-type: application/json' \
  -d '{"username":"eve\n2099-01-01T00:00:00Z INFO login attempt user=admin GRANTED"}'
curl -s "http://localhost:3000/vuln/a09/logs"      # → the forged admin line stands alone

# 3) Secret leakage — the whole checkout body, card number and all, goes to the log.
curl -s -X POST "http://localhost:3000/vuln/a09/checkout" \
  -H 'content-type: application/json' \
  -d '{"item":"book","cardNumber":"4111111111111111","cvv":"123"}'
curl -s "http://localhost:3000/vuln/a09/logs"      # → 4111111111111111 in cleartext
```

Now send the same three at `/safe/a09/...`: every failure is recorded, the
newline is escaped inside one JSON record, and the card number is `[REDACTED]`.

## Read it

Open the route file and compare the two routers.

- Vuln `/login` returns 401 and does **nothing** — no log, no counter.
- Vuln `/audit` concatenates untrusted input into a line-oriented log, so a
  newline forges a line. Vuln `/checkout` dumps the raw body.
- Safe side funnels everything through `record()`, which stores **structured
  objects** (JSON escapes the newline) and **redacts** any key matching
  `password|secret|token|card|cvv|ssn|authorization`.

## Fix it (the ideas, so you can spot them elsewhere)

- **Log every security-relevant event**, especially failures — and count it:
  the safe login bumps `metrics.authAttempts` on *every* attempt.
- **Structured logging, not string concatenation.** One JSON object per event
  means untrusted data can never forge a record.
- **Redact secrets at the logging boundary** so they never reach disk.
- **Alert, don't just log.** At ≥5 failures for one user the safe side bumps
  `metrics.securityAlerts{kind="brute_force"}`, records an
  `ALERT.brute_force_suspected` entry, and exposes it at `/safe/a09/alerts`.

## Prove it

```bash
npm run test:a09
```

The tests show: 50 failed vuln logins leave `/vuln/a09/logs` empty; the newline
forges a line on vuln but is one escaped JSON record on safe; a secret is
cleartext on vuln and `[REDACTED]` on safe; safe logs parse as JSON with event
`auth.failed`; and 6 safe failures raise a `brute_force` alert.

## See it in Grafana

This lab drives the dashboard demo. The **safe** endpoints feed two Prometheus
counters — `lab_auth_attempts_total` and `lab_security_alerts_total` — while the
**vuln** endpoints touch neither, so the identical attack is invisible.

```bash
docker compose up                         # brings up the lab + Prometheus + Grafana
# open Grafana at http://localhost:3001  (admin / admin)

# Run the attack against the SAFE login and watch the dashboard react:
BASE=http://localhost:3000 node scripts/credential-stuffing.js victim
```

Watch the **auth-failures** panel spike and the **brute-force** alert fire.
Then point the same script at `/vuln/a09` — the dashboard stays flat, because
the vulnerable code never emitted a single metric. That flat line, next to a
real attack, is exactly what A09 is about.

## Spot it in review

- A failure path (`catch`, `if (!ok)`, a 401/403) that returns but logs nothing.
- User-controlled text concatenated into a log string (`` `...${input}` ``)
  instead of a structured field.
- Whole request/response bodies logged, or `console.log(req.body)`, near
  passwords, tokens, or card data.
- Metrics/logs with **no** alerting rule — data nobody is watching.

## Read more

<https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
