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
    text: `Another flawless quarter at NullTail 🟢 Zero security incidents on record — literally, we don't record any. Failed logins? We don't log them. Brute force? Never seen one (because we're not looking). 😎

Our secret: if you don't collect the evidence, there's nothing to investigate. Peace of mind through willful blindness. 🧘

Meanwhile the "paranoid" fixed service next door counts every attempt, redacts secrets, and actually PAGES on brute force. Exhausting.

#observability #uptime #ignoranceisbliss #greendashboard #devops`,
  },
  profile: {
    headline: 'Head of "It’s Fine" Ops @ NullTail · sees no evil',
    about: `I run the quietest SOC in the business — because nothing is ever logged. Failed logins vanish. I concatenate raw usernames into my log file, so a well-placed newline lets you write your own log lines. And I dump entire request bodies to disk, card numbers and all.

Attack my login below. On /vuln, hammer it forever and leave no trace — /logs stays empty, /alerts doesn't even exist. On /safe, run the login ~6 times and watch a brute-force ALERT appear at /alerts and light up Grafana (http://localhost:3001), while /vuln shows nothing. Then forge a log line, and try leaking a card number through checkout.`,
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
        expect: {
          vuln: 'the full card number lands in /logs verbatim',
          safe: 'cardNumber and cvv show as [REDACTED]',
        },
      },
    ],
  },
};
