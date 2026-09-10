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
    summary: `Weaknesses around proving identity that go well past the password comparison itself — no rate limiting or lockout, default credentials left in place, an error message that confirms which accounts exist, breached passwords accepted at signup, and a session id that survives login instead of rotating.`,
  },
  profile: {
    headline: 'Head of Identity @ PassKey-Optional · "the password compare is the easy part (and the only part we did)"',
    about: `Authentication failures cover everything around proving identity besides the password comparison itself: rate limiting, lockouts, session handling, default credentials, and whether a breached password is even rejected at signup. A login can get every individual check "right" and still be trivially attackable if these surrounding controls are missing.

That's the trap with this category — the part everyone tests (does the right password work?) is rarely the part that's actually broken.

Try it below: log in with default credentials, change only the username and watch the error message reveal whether the account exists, register with a known-breached password, or plant a session id and see if it survives login.`,
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
        code: {
          lang: 'js',
          intro: 'Auth failures are everything AROUND the password check: oracles, defaults, no throttle.',
          vuln: `// distinct errors = a username oracle; default admin/admin honoured; no throttling
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
if (!user) return res.status(401).json({ error: 'No such user' });         // oracle
if (user.password_md5 !== md5(password || ''))
  return res.status(401).json({ error: 'Incorrect password' });            // oracle`,
          safe: `// lockout BEFORE any password work; ONE generic error; breached passwords refused
if ((failures.get(username) || 0) >= LOCKOUT_THRESHOLD)
  return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
const ok = user && scryptVerify(password || '', user.password_scrypt);
if (!ok) { failures.set(username, fails + 1); return res.status(401).json({ error: GENERIC_ERROR }); }
if (BREACHED.has(password))                                    // this is what stops admin/admin
  return res.status(403).json({ error: 'This password appeared in a breach. You must reset it.' });`,
        },
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
        code: {
          lang: 'js',
          intro: 'Session fixation: reusing a pre-login (attacker-known) session id after authentication.',
          vuln: `// session fixation: an attacker-planted sid is reused as the authenticated session
const planted = parseCookies(req).sid;
const sid = planted ? sessions.weak.login(planted, user.id) : sessions.weak.create(user.id);
res.setHeader('Set-Cookie', \`sid=\${sid}\`);
res.json({ loggedIn: true, sid, /* ... */ });`,
          safe: `// mint a brand-new high-entropy id on every login; discard whatever the client presented
const oldSid = parseCookies(req).sid;
const sid = sessions.strong.login(oldSid, user.id);   // rotates the id
res.setHeader('Set-Cookie', \`sid=\${sid}; HttpOnly; Secure; SameSite=Strict; Path=/\`);`,
        },
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
        code: {
          lang: 'js',
          intro: 'Accepting breached/trivial passwords — a check against a breach corpus is the fix.',
          vuln: `// accepts ANY password, including breached and trivial ones
vuln.post('/register', (req, res) => {
  const { username, password } = req.body;
  res.json({ registered: true, username, passwordLength: (password || '').length });
});`,
          safe: `// reject breached passwords FIRST, then enforce a length floor (length beats composition rules)
if (BREACHED.has(pw))
  return res.status(400).json({ error: 'That password has appeared in a breach corpus.' });
if (pw.length < 12)
  return res.status(400).json({ error: 'Password must be at least 12 characters.' });
res.json({ registered: true, username });`,
        },
        expect: { vuln: 'registered:true for any password, breached or trivial', safe: 'HTTP 400 — breached corpus / under 12 chars' },
      },
    ],
  },
};
