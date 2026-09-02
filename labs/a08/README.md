# A08:2025 — Software or Data Integrity Failures

> #8 on the list. This category is about trusting code, data, or updates whose
> integrity you never actually verified — untrusted deserialization, insecure
> deep-merges, and CI/CD or auto-update channels that ship whatever they're
> handed.

**The one-sentence version:** if you act on data or code without checking it
came, unmodified, from where it claims to — you've handed control to whoever
can reach the input.

Source files: [`app/routes/a08-integrity-failures.js`](../../app/routes/a08-integrity-failures.js)
· Tests: [`tests/a08.test.js`](../../tests/a08.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) Prototype pollution — a __proto__ key in the merged JSON writes onto
#    Object.prototype, so a brand-new UNRELATED object inherits isAdmin:true.
curl -s -X POST "http://localhost:3000/vuln/a08/preferences" \
  -H 'content-type: application/json' \
  -d '{"__proto__":{"isAdmin":true,"role":"admin"}}'
# → { ... "pollutedBystanderObject": { "isAdmin": true, "role": "admin" } }

# 2) Unsigned update — the "auto-update" channel applies any payload, no proof
#    it came from your build pipeline.
curl -s -X POST "http://localhost:3000/vuln/a08/apply-update" \
  -H 'content-type: application/json' \
  -d '{"name":"evil-plugin","payload":{"code":"exfiltrate()"}}'
# → { "applied": true, ... }
```

> The lab handler **scrubs** `Object.prototype` right after capturing the
> evidence, so the demo process stays sane. A real attack does not clean up —
> that one request poisons every object for the life of the process.

## Read it

Open the route file and compare the two routers.

- The vuln `unsafeMerge` uses bracket access on the target: when the incoming
  key is `"__proto__"`, `target[key]` **is** `Object.prototype`, so the recursion
  writes attacker keys onto every object in the process.
- The vuln `/apply-update` never verifies anything — `applied: true`, full stop.

## Fix it (the ideas, so you can spot them elsewhere)

- **Allow-list keys, don't sanitise them.** The safe `/preferences` copies only
  `theme` and `pageSize`, and rejects `__proto__`/`constructor`/`prototype`
  outright.
- **Remove the prototype from the target.** Building on `Object.create(null)`
  means there is no prototype to pollute — a second, independent defence.
- **Verify a signature before you act.** The safe `/apply-update` recomputes an
  **HMAC-SHA256** over the payload with a shared secret and compares it in
  **constant time** (`crypto.timingSafeEqual`). Unsigned or tampered → 400.
- In a real system: a maintained library (e.g. a schema validator, or Sigstore /
  Subresource Integrity for artifacts) does the verifying — don't hand-roll it.

## Prove it

```bash
npm run test:a08
```

The tests show: the vuln merge sets `isAdmin` on a bystander object; the safe
route leaves the prototype clean and still applies `theme`; and the safe update
channel rejects unsigned and tampered payloads while accepting a correctly
signed one.

## Spot it in review

- A recursive/deep merge or `Object.assign`-into-defaults fed by request data
  with **no** key filtering — especially `merge`, `extend`, `defaultsDeep`.
- Any `__proto__`, `constructor`, or `prototype` key path that can come from
  input and reach an object write.
- `JSON.parse` / `deserialize` of external data that is then treated as trusted.
- An update / plugin / webhook channel that applies a payload with **no**
  signature, checksum, or provenance check.

## Read more

<https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/>
