'use strict';
// A02:2025 — Security Misconfiguration. The bugs aren't clever: a fingerprinting
// header, a listable folder leaking a forgotten .env.backup, a live /debug env
// dump, a stack trace mailed to the attacker, a flagless cookie. The persona is
// a "ship it on Friday" ops lead who never flipped a single default.
module.exports = {
  persona: {
    name: 'Chad Beauregard',
    title: 'Head of DevOps at LaunchPad Cloud',
    company: 'LaunchPad Cloud',
    avatar: 'CB',
    color: '#dd6b20',
    banner: 'linear-gradient(120deg,#7b341e,#dd6b20 60%,#f6ad55)',
    location: 'Austin, Texas',
    connections: '9,001',
  },
  post: {
    time: '5h',
    reactions: 173, comments: 62, reposts: 24,
    headline: 'LaunchPad Cloud: zero-config, zero-friction, zero-downtime 🚀',
    cta: 'Our "sensible defaults" mean we never touch config',
    summary: `Insecure defaults left switched on: a fingerprinting header, a listable directory that leaks a forgotten backup file, a debug endpoint that dumps the process environment, a stack trace mailed back to the client, a cookie missing its security flags. Nothing exotic — just settings nobody ever changed before shipping to production.`,
  },
  profile: {
    headline: 'Head of DevOps @ LaunchPad Cloud · "the defaults are fine"',
    about: `Security misconfiguration happens when a system ships with insecure defaults, unnecessary features left switched on, or hardening steps skipped under time pressure. It rarely takes a clever exploit — an exposed debug endpoint, a directory listing, a verbose error page, or a cookie missing its security flags is often enough on its own to leak secrets or widen the attack surface.

The failures tend to compound: one forgotten setting leads directly to the next, and none of them require a single line of "hacking" to find.

Try it below: browse a directory nobody meant to expose, download a leftover backup file, dump the process environment through a debug endpoint, crash a route and read the stack, then compare the session cookie's flags side by side.`,
    highlights: ['Fingerprinting headers', 'Directory listing', 'Leaked .env.backup', 'Debug env dump', 'Stack-trace disclosure', 'Flagless cookies'],
  },
  bench: {
    intro: 'LaunchPad Cloud on its factory defaults. Every action hits the real broken and fixed endpoints — run both and diff the response (and the headers).',
    actions: [
      {
        id: 'listing',
        title: 'Browse the static /files directory',
        description: 'Directory listing is on. A folder nobody meant to expose lists everything inside it — including files you would never link to.',
        method: 'GET', path: '/files/', render: 'iframe',
        hint: 'The listing links straight to .env.backup.',
        code: {
          lang: 'js',
          intro: 'A static directory with listing enabled exposes files you would never link to.',
          vuln: `// listing ON + dotfiles allowed → the whole folder is browsable
vuln.get('/files/', (req, res) => {
  const entries = fs.readdirSync(PUBLIC_FILES_DIR);
  const links = entries.map((f) => \`<li><a href="\${f}">\${f}</a></li>\`).join('');
  res.type('html').send(\`<h1>Index of /files</h1><ul>\${links}</ul>\`);
});
vuln.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'allow', index: false }));`,
          safe: `// no listing handler + dotfiles ignored → the directory index falls through to 404
safe.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'ignore', index: false }));`,
        },
        expect: { vuln: 'renders an index listing every file in the folder', safe: '404 — no listing handler exists' },
      },
      {
        id: 'dotfile',
        title: 'Download the leaked .env.backup',
        description: 'A hurried `cp .env .env.backup` under a web root. With dotfiles allowed, anyone can just fetch it. (Fake secrets — this file is bait.)',
        method: 'GET', path: '/files/.env.backup',
        hint: 'Read the STRIPE_KEY / DATABASE_URL / SESSION_SECRET it leaks.',
        code: {
          lang: 'js',
          intro: 'The `dotfiles: "allow"` default serves a leftover .env.backup over HTTP.',
          vuln: `// \`dotfiles: 'allow'\` serves the forgotten backup to anyone who asks for it
vuln.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'allow', index: false }));
// GET /vuln/a02/files/.env.backup → 200, STRIPE_KEY / DATABASE_URL / SESSION_SECRET in the body`,
          safe: `// \`dotfiles: 'ignore'\` makes every dotfile 404
// (better still: never keep secrets under a web root — this is defence in depth)
safe.use('/files', express.static(PUBLIC_FILES_DIR, { dotfiles: 'ignore', index: false }));`,
        },
        expect: { vuln: 'serves the backup with its "secrets" in the body', safe: '404 — dotfiles are ignored' },
      },
      {
        id: 'debug',
        title: 'Dump the environment via /debug',
        description: 'A debug endpoint that returns process.env. Handy in dev, catastrophic in prod: it hands over every secret the process booted with.',
        method: 'GET', path: '/debug',
        code: {
          lang: 'js',
          src: { safe: { anchor: "if (process.env.ENABLE_DEBUG_ENDPOINTS" } },
          intro: 'A live /debug endpoint returns process.env — handy in dev, catastrophic in prod.',
          vuln: `// a debug endpoint that dumps the whole process environment — every secret it booted with
vuln.get('/debug', (req, res) => res.json({ env: process.env }));`,
          safe: `// mounted ONLY behind an explicit opt-in flag, so the default (unset) is safe
if (process.env.ENABLE_DEBUG_ENDPOINTS === '1') {
  safe.get('/debug', (req, res) => res.json({ env: process.env }));
}`,
        },
        expect: { vuln: 'returns the full process environment as JSON', safe: '404 — mounted only behind an explicit opt-in flag' },
      },
      {
        id: 'boom',
        title: 'Crash a route and read the error',
        description: 'Trigger an unhandled error. The verbose handler returns the raw stack trace — file paths, versions, and the DB error message.',
        method: 'GET', path: '/boom',
        hint: 'Note the internal hostname and user leaked in the message.',
        code: {
          lang: 'js',
          src: { vuln: { anchor: 'vuln.use((err,' }, safe: { anchor: 'safe.use((err,' } },
          intro: 'A verbose error handler mails the stack trace (file paths, versions, secrets) to the attacker.',
          vuln: `// the error handler returns the raw stack trace to the client
vuln.use((err, req, res, next) => {
  res.status(500).type('text').send(err.stack);   // leaks paths, versions, the DB message
});`,
          safe: `// log the detail server-side under a reference id; return an opaque error to the client
safe.use((err, req, res, next) => {
  const reference = crypto.randomUUID();
  console.error(JSON.stringify({ event: 'unhandled_error', reference, message: err.message, stack: err.stack }));
  res.status(500).json({ error: 'Internal server error', reference });
});`,
        },
        expect: { vuln: 'returns the full stack trace as text', safe: 'opaque "Internal server error" + a reference id to quote in a ticket' },
      },
      {
        id: 'cookie',
        title: 'Log in and inspect the session cookie',
        description: 'Same JSON both sides — the difference is the Set-Cookie header. Open your devtools Network tab (or read the raw headers) to compare.',
        method: 'GET', path: '/login-demo',
        hint: 'vuln: no HttpOnly / Secure / SameSite. safe: all three set.',
        code: {
          lang: 'js',
          intro: 'A flagless session cookie is readable by JS (XSS) and sent cross-site (CSRF).',
          vuln: `// a session cookie set by hand, with no security attributes
res.setHeader('Set-Cookie', 'demo_session=s3ssion-abc123; Path=/');
// no HttpOnly (JS can read it → XSS), no Secure (sent over plain HTTP), no SameSite (CSRF)`,
          safe: `// every flag set: HttpOnly (no JS access) + Secure (HTTPS only) + SameSite (CSRF hardening)
res.cookie('demo_session', 's3ssion-abc123', {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
});`,
        },
        expect: { vuln: 'sets demo_session with zero flags (XSS-readable, CSRF-able)', safe: 'sets HttpOnly + Secure + SameSite=Lax' },
      },
    ],
  },
};
