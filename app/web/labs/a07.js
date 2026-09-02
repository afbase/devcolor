'use strict';
// A07:2025 — Authentication Failures. Almost none of this is the password
// comparison — it's throttling, MFA, session handling, default creds, and
// breached passwords. Persona: an "identity" lead who thinks admin/admin is a
// feature. The profile page IS the live target — actions hit /vuln/a07 & /safe/a07.
module.exports = {
  persona: {
    name: 'Otto Loggin',
    title: 'Head of Identity at PassKey-Optional',
    company: 'PassKey-Optional',
    avatar: 'OL',
    color: '#2a9d8f',
    banner: 'linear-gradient(120deg,#1d3557,#2a9d8f 60%,#83c5be)',
    location: 'Remote',
    connections: '3,140',
  },
  post: {
    time: '1h',
    reactions: 188, comments: 52, reposts: 22,
    headline: 'PassKey-Optional: auth, but make it optional',
    cta: 'admin/admin still works and we’re proud of it',
    text: `Unpopular opinion: rate limiting is hostile to power users 🙅 At PassKey-Optional we kept the login SIMPLE.

The password check is technically correct! We also kept the default admin/admin (migration risk 🤷), tell you exactly which field was wrong so you can fix it faster, happily accept "password123", and reuse whatever session id your browser shows up with. Efficiency!

MFA is on the roadmap. The roadmap is also optional.

#identity #devex #login #nolockout #security`,
  },
  profile: {
    headline: 'Head of Identity @ PassKey-Optional · "the password compare is the easy part (and the only part we did)"',
    about: `The login below verifies passwords "correctly" and is still broken five ways: default creds, no throttling, a username oracle, breached passwords accepted, and session fixation.

Log in as admin/admin. Change just the username and watch the error message tattle on whether the account exists. Register with "password123". Plant a session id and see it survive login. The safe side locks accounts, blocks breached passwords, gives ONE identical error, and rotates the session on every login.`,
    highlights: ['Default credentials', 'Credential stuffing / spray', 'Username oracle', 'Breached-password reuse', 'Session fixation'],
  },
  bench: {
    intro: 'PassKey-Optional’s login. Run vuln vs safe — the safe side adds everything AROUND the password check: lockout, a breach block, a single generic error, and a fresh session id.',
    actions: [
      {
        id: 'login-default-oracle',
        title: 'Default creds + username oracle',
        description: 'Log in as admin/admin — the default nobody removed. Then change ONLY the username to probe the oracle: the vuln returns different errors for a real vs fake username; the safe returns one generic error and blocks the breached admin password outright.',
        method: 'POST', path: '/login', bodyType: 'form',
        inputs: [
          { name: 'username', label: 'Username', default: 'admin', in: 'body' },
          { name: 'password', label: 'Password', default: 'admin', in: 'body' },
        ],
        hint: 'Oracle test: keep password "x" and switch username between "alice" (real) and "nope" (fake). Vuln says "Incorrect password" vs "No such user"; safe says the same thing for both.',
        expect: { vuln: 'admin/admin logs in; errors reveal whether a user exists', safe: 'admin/admin → 403 breached; every failure → one generic error' },
      },
      {
        id: 'login-fixation',
        title: 'Session fixation (plant a session id)',
        description: 'Plant a session id via the cookie, then log in with valid, non-breached creds. The vuln keeps YOUR planted id as the authenticated session (it echoes it back). The safe side mints a brand-new high-entropy id and discards yours.',
        method: 'POST', path: '/login', bodyType: 'form',
        headers: { cookie: 'sid={sid}' },
        inputs: [
          { name: 'username', label: 'Username', default: 'dana', in: 'body' },
          { name: 'password', label: 'Password', default: 'trombone-glacier-42-mango', size: 260, in: 'body' },
          { name: 'sid', label: 'Planted session id', default: 'attacker-fixed-session-123', size: 260 },
        ],
        hint: 'Dana’s password is long and NOT in the breach corpus, so the safe login actually succeeds and you can see it rotate the id. On vuln, the response’s sid equals what you planted.',
        expect: { vuln: 'loggedIn:true and sid = your planted "attacker-fixed-session-123"', safe: 'loggedIn:true with a fresh server-minted id (planted id discarded)' },
      },
      {
        id: 'register-breached',
        title: 'Register with a breached password',
        description: 'The vuln registration accepts any password, including ones already in a breach corpus. The safe side rejects breached passwords first, then enforces a 12-character floor (length beats composition rules).',
        method: 'POST', path: '/register', bodyType: 'form',
        inputs: [
          { name: 'username', label: 'Username', default: 'newuser', in: 'body' },
          { name: 'password', label: 'Password', default: 'password123', size: 220, in: 'body' },
        ],
        hint: 'Try "password123" (breached → safe 400), then a short unique one like "abc" (safe: too short), then a long unique passphrase (safe accepts).',
        expect: { vuln: 'registered:true for any password, breached or trivial', safe: 'HTTP 400 — breached corpus / under 12 chars' },
      },
    ],
  },
};
