# Lab authoring spec (shared conventions)

Every category `aNN` ships three files that follow the **A01 reference exactly**:

- `app/routes/aNN-<slug>.js` — exports `{ vuln, safe }` (two `express.Router()`s).
  Mounted by the server at `/vuln/aNN` and `/safe/aNN`.
- `labs/aNN/README.md` — Break it → Read it → Fix it → Prove it → “Spot it in review”.
- `tests/aNN.test.js` — uses `tests/helpers.js`; each test breaks the vuln, then proves the safe fix.

**Read these first — they are the canonical template:**
`app/routes/a01-broken-access-control.js` and `tests/a01.test.js`.

## Shared API (import from these; do not re-implement)

```js
const { db, md5, scryptHash, scryptVerify } = require('../db');
const { escapeHtml, parseCookies } = require('../lib/util');
const sessions = require('../lib/sessions');           // sessions.weak / sessions.strong
const { assertPublicUrl } = require('../lib/ssrf-guard');
const { metrics } = require('../metrics');             // Prometheus counters
```

Metrics counters (call `.inc({label})`):
- `metrics.authAttempts` labels `{result:'success'|'failure'|'lockout'|'breached'}`
- `metrics.accessDenied` labels `{resource}`
- `metrics.ssrfAttempts` labels `{result:'allowed'|'blocked'}`
- `metrics.securityAlerts` labels `{kind}`  (e.g. `'brute_force'`)

## Database (migrated + seeded; in-memory per test process)

Tables: `users(id,username,email,full_name,role,password_md5,password_scrypt,mfa_enabled,failed_logins,created_at)`,
`accounts(user_id,balance_cents)`, `invoices(id,user_id,amount_cents,memo)`,
`coupons(code,percent_off,times_used,max_uses)`, `audit_log`, `guestbook(id,author,body,created_at)`,
`support_tickets(id,user_id,subject,body,status)`, `webhooks(id,user_id,label,target_url)`,
`artifacts(id,name,version,applied)`.

Seed users (username / password / role): `alice`/`password123`/user, `bob`/`hunter2`/user,
`carol`/`correct horse battery staple`/user(mfa), `admin`/`admin`/admin, `dana`/`trombone-glacier-42-mango`/user(mfa),
`agent`/`summer-lantern-goose-19`/agent. Invoices 1001–1005 (1004 is Carol's confidential SEVERANCE).
Coupons `WELCOME10` (10%, max 1) and `LOYAL25` (25%, max 3).

## Test helper

```js
const { startLab, startInternalService } = require('./helpers');
const lab = startLab();                 // lab.get/post/put/del(path,{json|form|headers}); lab.stop()
const internal = startInternalService();// internal.url() -> loopback URL; blocked by safe SSRF guard
```

## Style
- Two clearly commented sections: `// VULNERABLE` and `// SECURE`.
- Comments explain *why*, and are written to be read aloud in a workshop.
- The fix is the smallest honest form of the idea; note where a real app would use a library.
- Keep the vuln and safe routes at the SAME paths so `curl` can diff them.
- Do NOT edit shared files (server.js, db/*, lib/*, metrics.js, package.json). Only your aNN files.
