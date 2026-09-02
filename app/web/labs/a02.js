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
    text: `Just migrated LaunchPad to prod in a single afternoon 😎 No YAML, no hardening checklist, no fuss — we ship on the framework defaults because the framework knows best, right?

Bonus: I left the /debug endpoint on so on-call can eyeball the environment, and our static /files folder means marketing can drop brochures without a deploy. Efficiency! 💪

"Security review" is just friction we haven't scheduled. We'll harden it after the launch party.

#devops #shipit #cloudnative #movefast #nofilter`,
  },
  profile: {
    headline: 'Head of DevOps @ LaunchPad Cloud · "the defaults are fine"',
    about: `I run the platform that runs your startup. LaunchPad is fast because I don't waste time on config: default headers, an open static folder, a debug endpoint for the on-call rotation, and verbose errors so my team can actually fix things.

Go ahead — poke at the bench below. Read the directory index for a folder I forgot about. Download the file I definitely didn't mean to leave there. Ask /debug what secrets I booted with. Crash a route and read the stack. Then flip to Fixed and watch every one of those doors close.`,
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
        expect: { vuln: 'renders an index listing every file in the folder', safe: '404 — no listing handler exists' },
      },
      {
        id: 'dotfile',
        title: 'Download the leaked .env.backup',
        description: 'A hurried `cp .env .env.backup` under a web root. With dotfiles allowed, anyone can just fetch it. (Fake secrets — this file is bait.)',
        method: 'GET', path: '/files/.env.backup',
        hint: 'Read the STRIPE_KEY / DATABASE_URL / SESSION_SECRET it leaks.',
        expect: { vuln: 'serves the backup with its "secrets" in the body', safe: '404 — dotfiles are ignored' },
      },
      {
        id: 'debug',
        title: 'Dump the environment via /debug',
        description: 'A debug endpoint that returns process.env. Handy in dev, catastrophic in prod: it hands over every secret the process booted with.',
        method: 'GET', path: '/debug',
        expect: { vuln: 'returns the full process environment as JSON', safe: '404 — mounted only behind an explicit opt-in flag' },
      },
      {
        id: 'boom',
        title: 'Crash a route and read the error',
        description: 'Trigger an unhandled error. The verbose handler returns the raw stack trace — file paths, versions, and the DB error message.',
        method: 'GET', path: '/boom',
        hint: 'Note the internal hostname and user leaked in the message.',
        expect: { vuln: 'returns the full stack trace as text', safe: 'opaque "Internal server error" + a reference id to quote in a ticket' },
      },
      {
        id: 'cookie',
        title: 'Log in and inspect the session cookie',
        description: 'Same JSON both sides — the difference is the Set-Cookie header. Open your devtools Network tab (or read the raw headers) to compare.',
        method: 'GET', path: '/login-demo',
        hint: 'vuln: no HttpOnly / Secure / SameSite. safe: all three set.',
        expect: { vuln: 'sets demo_session with zero flags (XSS-readable, CSRF-able)', safe: 'sets HttpOnly + Secure + SameSite=Lax' },
      },
    ],
  },
};
