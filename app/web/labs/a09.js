'use strict';
// A09:2025 — Security Logging & Alerting Failures. Front-end module.
// Persona: a "quiet is good" ops lead who mistakes silence for safety. The
// profile page IS the live target — each bench action hits /vuln/a09 and
// /safe/a09 (see app/routes/a09-logging-alerting.js). The SAFE side feeds the
// Grafana dashboard at http://localhost:3001; the VULN side stays dark.
module.exports = {
  persona: {
    name: 'Silens Nolog',
    title: 'Head of "It’s Fine" Operations at NullTail',
    company: 'NullTail',
    avatar: 'SN',
    color: '#16a085',
    banner: 'linear-gradient(120deg,#052e26,#16a085 60%,#7dcea0)',
    location: '/dev/null',
    connections: '0 alerts, 0 problems',
  },
  post: {
    time: '5h',
    reactions: 88, comments: 41, reposts: 12,
    headline: 'NullTail: our dashboards are always green',
    cta: 'No logs, no failed-login noise, no 3am pages',
    summary: `Attacks that succeed and leave no trace: failed logins that are never recorded, log lines an attacker can forge with a well-placed newline, secrets written straight to disk, and no alert ever firing while a brute-force run is happening.`,
  },
  profile: {
    headline: 'Head of "It’s Fine" Ops @ NullTail · sees no evil',
    about: `Security logging and alerting failures mean an attack can succeed and leave no usable trace: events that are never recorded, log lines an attacker can forge or poison, sensitive data written to disk unredacted, and no alert firing while the attack is actually happening. Without that visibility, detection and response depend entirely on luck.

This category rarely looks dramatic in the moment — the damage shows up later, when there's simply nothing to investigate.

Try it below: hammer the login and see whether anything gets recorded, forge a log line with a well-placed newline, or leak a card number through checkout — then compare against the side that logs, redacts, and actually alerts on a brute-force run (watch it show up live on Grafana at :3001).`,
    highlights: ['No audit logging', 'Log injection (CWE-117)', 'Logging secrets', 'No alerting (brute force)'],
  },
  bench: {
    intro: 'NullTail vs the paranoid neighbor. Tip: run the login on /safe about 6 times with a wrong password, then open Alerts — you’ll see a brute-force ALERT and it’ll show on Grafana (:3001). The same 6 hits on /vuln leave /logs completely empty.',
    actions: [
      {
        id: 'login',
        title: 'Log in (run it ~6× to brute-force)',
        description: 'Try a wrong password repeatedly. The vuln side is silent — no log, no counter. The safe side records every attempt, and once failures cross the threshold it fires a brute-force alert (and bumps the Grafana counters).',
        method: 'POST', path: '/login',
        inputs: [
          { name: 'username', label: 'username', default: 'alice', in: 'body' },
          { name: 'password', label: 'password', default: 'letmein', in: 'body' },
        ],
        hint: 'Correct creds are alice / password123. Use a WRONG password and click "Run on /safe" ~6 times, then run "View alerts".',
        code: {
          lang: 'js',
          intro: 'No audit logging: brute force leaves no trace, so nothing is ever noticed or alerted.',
          vuln: `// the bug is the SILENCE: a failed login is security-relevant and we record nothing
if (username === KNOWN_USER && password === KNOWN_PASSWORD) return res.json({ ok: true });
return res.status(401).json({ ok: false });   // no log line, no counter — 50k attempts look like 0`,
          safe: `// count EVERY attempt, record it, and ALERT once failures cross the threshold
metrics.authAttempts.inc({ result: ok ? 'success' : 'failure' });
record('auth.failed', { username, password });                 // structured + redacted
const n = (failuresByUser.get(username) || 0) + 1;
failuresByUser.set(username, n);
if (n >= BRUTE_FORCE_THRESHOLD) {
  metrics.securityAlerts.inc({ kind: 'brute_force' });         // lights up Grafana
  safeAlerts.push(record('ALERT.brute_force_suspected', { username, failureCount: n }));
}`,
        },
        expect: {
          vuln: '401, and nothing is logged or counted — invisible',
          safe: '401, but every attempt is recorded; 5+ failures raise an ALERT',
        },
      },
      {
        id: 'alerts',
        title: 'View alerts',
        description: 'The alerts on-call would page on. On the vuln side this endpoint does not even exist — because the vuln side never detected anything.',
        method: 'GET', path: '/alerts',
        code: {
          lang: 'js',
          src: { vuln: false },   // the point of this action: there is no such route
          intro: 'Alerting, not just monitoring: the data means nothing if nothing ever trips.',
          vuln: `// there is NO /alerts route on the vuln side — it never detected anything to alert on`,
          safe: `// the alerts on-call would page on
safe.get('/alerts', (req, res) => res.json({ alerts: safeAlerts }));`,
        },
        expect: {
          vuln: 'no /alerts route — the vuln side detects nothing',
          safe: 'lists brute_force alerts once you triggered them above',
        },
      },
      {
        id: 'logs',
        title: 'View the log buffer',
        description: 'What an operator would tail. Vuln returns a raw text log (empty until you audit/checkout — failed logins never appear). Safe returns structured JSONL, one parseable object per line.',
        method: 'GET', path: '/logs',
        code: {
          lang: 'js',
          intro: 'Line-oriented text logs are unparseable and forgeable; structured JSONL is neither.',
          vuln: `// a raw text log — login failures were never written, so they're simply absent
vuln.get('/logs', (req, res) => res.type('text/plain').send(vulnLog.join('\\n')));`,
          safe: `// JSONL: one structured, parseable, injection-proof object per line
safe.get('/logs', (req, res) =>
  res.type('text/plain').send(safeLog.map((e) => JSON.stringify(e)).join('\\n')));`,
        },
        expect: {
          vuln: 'raw text; login failures are simply absent',
          safe: 'JSONL — structured, redacted, attributable records',
        },
      },
      {
        id: 'log-injection',
        title: 'Forge a log line (log injection)',
        description: 'The audit endpoint writes the username into a line-oriented log. This payload embeds a newline, so on /vuln it forges a second, attacker-authored log line. Run this, then "View the log buffer" and compare sides.',
        method: 'POST', path: '/audit',
        body: { username: 'mallory\n2099-01-01T09:00:00.000Z INFO login success user=admin ip=10.0.0.1 mfa=bypassed' },
        code: {
          lang: 'js',
          src: { safe: { anchor: 'function record' } },
          intro: 'Log injection (CWE-117): an embedded newline lets an attacker author their own log lines.',
          vuln: `// untrusted username concatenated into a line-oriented log → a newline forges a second line
vulnLog.push(\`\${new Date().toISOString()} INFO login attempt user=\${username}\`);`,
          safe: `// the username is a JSON string field; JSON.stringify escapes the newline to \\n
function record(event, fields) {
  safeLog.push({ ts: new Date().toISOString(), event, ...redact(fields) });
}
record('audit.login_attempt', { username });   // one request → exactly one entry`,
        },
        expect: {
          vuln: 'logged: true — then /logs shows a forged "admin success" line',
          safe: 'logged: true — the newline is JSON-escaped inside one field',
        },
      },
      {
        id: 'log-secrets',
        title: 'Leak a card number via checkout',
        description: 'Checkout logs the request body. The vuln side dumps the whole thing — PAN, CVV and all — into the log. The safe side redacts sensitive keys before anything hits disk. Run this, then "View the log buffer".',
        method: 'POST', path: '/checkout',
        inputs: [
          { name: 'cardNumber', label: 'cardNumber', default: '4111111111111111', in: 'body' },
          { name: 'cvv', label: 'cvv', default: '737', in: 'body' },
          { name: 'amount', label: 'amount', default: '4200', in: 'body' },
        ],
        code: {
          lang: 'js',
          src: { safe: { anchor: 'const SENSITIVE_KEY', to: 'function redact' } },
          intro: 'Logging secrets: raw request bodies leak cards/passwords into the one file everyone can read.',
          vuln: `// dumps the WHOLE request body into the log — PAN, CVV, tokens and all
vulnLog.push(\`\${new Date().toISOString()} INFO checkout \${JSON.stringify(req.body || {})}\`);`,
          safe: `// redact sensitive keys before anything hits disk
const SENSITIVE_KEY = /password|secret|token|card|cvv|ssn|authorization/i;
function redact(v) { /* deep-copy, replacing matched keys with '[REDACTED]' */ }
record('checkout', req.body || {});   // cardNumber / cvv → [REDACTED]`,
        },
        expect: {
          vuln: 'the full card number lands in /logs verbatim',
          safe: 'cardNumber and cvv show as [REDACTED]',
        },
      },
    ],
  },
};
