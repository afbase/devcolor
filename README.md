# OWASP Top 10:2025 — a hands-on hour for engineers

A companion lab to the talk deck. After (or during) a one-hour walkthrough of
the [OWASP Top 10:2025](https://owasp.org/Top10/2025/), an engineer can **break
each vulnerability, read the two-line fix, and prove it with a test** — on their
own laptop, in a few minutes each.

The front end is a **LinkedIn-style feed**: each of the ten categories is a
"post" from a (fictional, oblivious) company bragging about the feature they
just shipped. Click a post and you land on that persona's **profile page — a
live target** where you run the vulnerability yourself with a click, comparing
the broken and fixed endpoints side by side.

Under the hood every category is a matched pair of routes:

```
/vuln/aNN/...   the broken version
/safe/aNN/...   the same feature, fixed
```

The profile "bench" simply calls both and shows you the difference.

The full stack runs on Docker Compose: the vulnerable app, a **network-internal
service** you can only reach through the SSRF bug, **Prometheus**, and
**Grafana** dashboards that make the "logging & alerting" failures (A09) visible.

> [!WARNING]
> **This application is deliberately vulnerable.** Run it locally only — never
> deploy it, never expose it to a network you don't control, never point it at
> real data.

---

## Getting started

### Run the full stack: Docker Compose

You only need Docker Desktop (or Docker Engine + the Compose plugin).

```bash
git clone https://github.com/afbase/devcolor.git
cd devcolor
docker compose up --build        # first build takes a couple of minutes
```

Then open:

| URL | What |
|-----|------|
| <http://localhost:3000> | **The feed** — one post per lab; click through to each interactive profile |
| <http://localhost:3001> | **Grafana** (login `admin` / `admin`) — the A09 security dashboards |
| <http://localhost:9090> | **Prometheus** — raw metrics and alert rules |

Stop it with `Ctrl-C`, and `docker compose down -v` to remove the volumes.

> The `internal-api` service has **no published port** — it exists only on the
> Compose network. That's the point: the only way to reach it is through the
> app's SSRF vulnerability (lab A01).

### Prove your work

```bash
npm test            # every lab: break the vuln, then prove the fix. ~80 tests.
npm run test:a01    # just one category
```

### Reset the data

The database migrates and seeds itself on first boot. To wipe it:

```bash
npm run db:reset            # local
docker compose down -v      # docker (also clears Grafana)
```

## The ten categories

| # | Category | 2025 change | Lab |
|---|----------|-------------|-----|
| A01 | Broken Access Control | #1; SSRF folded in | [labs/a01](labs/a01/README.md) |
| A02 | Security Misconfiguration | ▲ #5 → #2 | [labs/a02](labs/a02/README.md) |
| A03 | Software Supply Chain Failures | expanded; survey #1 | [labs/a03](labs/a03/README.md) |
| A04 | Cryptographic Failures | ▼ #2 → #4 | [labs/a04](labs/a04/README.md) |
| A05 | Injection | ▼ #3 → #5 (XSS here) | [labs/a05](labs/a05/README.md) |
| A06 | Insecure Design | ▼ #4 → #6 | [labs/a06](labs/a06/README.md) |
| A07 | Authentication Failures | #7, renamed | [labs/a07](labs/a07/README.md) |
| A08 | Software or Data Integrity Failures | #8 | [labs/a08](labs/a08/README.md) |
| A09 | Security Logging & Alerting Failures | #9, "Monitoring"→"Alerting" | [labs/a09](labs/a09/README.md) |
| A10 | Mishandling of Exceptional Conditions | 🆕 new | [labs/a10](labs/a10/README.md) |

Each `labs/aNN/README.md` follows the same shape — **Break it → Read it → Fix it
→ Prove it** — and ends with a "spot it in code review" checklist.

## The website

Open <http://localhost:3000> for the feed. Every post is a lab; click the poster
(or **Open profile & try it →**) to reach `/lab/aNN`. On the profile, each
"bench" action has a 🔓 **Run on /vuln** and a 🔒 **Run on /safe** button and shows
the raw response — so you watch an IDOR leak someone else's invoice on `/vuln`
and get a `404` on `/safe`, or watch stored XSS actually execute in a live
frame. The lab's own chrome is locked down with a strict CSP; the vulnerable
endpoints it frames are not — that contrast is the point.

## How the observability demo works (A09)

The app exposes Prometheus metrics at `/metrics`. The **safe** endpoints record
security events (auth failures, denials, blocked SSRF, brute-force alerts); the
**vulnerable** ones don't. So when you run a brute-force script against
`/safe/a09`, the Grafana "Auth attempts" panel spikes and a **brute-force alert
fires** — but the identical attack on `/vuln/a09` leaves the dashboard flat.
That gap *is* A09.

```bash
# with the stack up, watch Grafana while this runs:
node scripts/credential-stuffing.js admin
```

## The slide deck

The 23-slide talk deck is [docs/OWASP_Top_10_2025.pptx](docs/OWASP_Top_10_2025.pptx)
(import into Google Slides or open in PowerPoint/Keynote — see [docs/SLIDES.md](docs/SLIDES.md)).
Facilitator notes: [docs/FACILITATOR.md](docs/FACILITATOR.md).

## Layout

```
docker-compose.yml         # lab + internal-api + prometheus + grafana
Dockerfile                 # the lab app image
app/
  server.js                # mounts /vuln/aNN and /safe/aNN; serves the feed + profiles; /metrics
  web/
    render.js              # server-rendered LinkedIn feed + profile pages
    labs/aNN.js            # per-lab persona, feed post, and interactive "bench" spec
  public/
    linkedin.css           # the feed/profile design system
    bench.js               # client renderer: turns a bench spec into a vuln/safe runner
  db/                      # migration runner + seed; opens SQLite (in-memory for tests)
  metrics.js               # Prometheus counters (the A09 backbone)
  lib/                     # cookies, HTML escaping, sessions, the SSRF guard
  routes/aNN-*.js          # the vuln + safe pair for each category, commented
db/migrations/*.sql        # schema migrations
internal-api/              # the network-internal SSRF target
monitoring/                # prometheus config + alerts; grafana provisioning + dashboards
labs/aNN/README.md         # break it / read it / fix it / prove it
tests/aNN.test.js          # exploits that fail-then-pass across the vuln→safe boundary
scripts/                   # doctor + copy-paste exploit demos
```

## A note on scope

These are teaching models, not a security product. The fixes show the *idea* in
the smallest honest form. In production, reach for maintained libraries —
`helmet`, `argon2`/`bcrypt`, a real rate limiter, an ORM with parameterization
on by default — rather than the hand-rolled versions here. Where that's true,
the lab says so.

## License

[MIT](LICENSE). The OWASP Top 10 content is © the OWASP Foundation (CC BY-SA 4.0);
this repo links to and paraphrases it for teaching.
