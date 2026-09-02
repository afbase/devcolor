'use strict';
// A05:2025 — Injection (SQLi, OS command injection, reflected + stored XSS).
// Persona: an over-eager "no-ORM, raw-SQL-is-faster" founder whose portal
// concatenates every input straight into an interpreter. The profile page IS
// the live target — each bench action hits /vuln/a05 and /safe/a05.
module.exports = {
  persona: {
    name: 'Roberta "Bobby" Tables',
    title: 'Founder & CTO at QueryCraft',
    company: 'QueryCraft',
    avatar: 'BT',
    color: '#b5179e',
    banner: 'linear-gradient(120deg,#3a0ca3,#b5179e 55%,#f72585)',
    location: 'Palo Alto, CA',
    connections: '9,001',
  },
  post: {
    time: '3h',
    reactions: 342, comments: 88, reposts: 41,
    headline: 'QueryCraft: raw SQL, raw speed, raw HTML',
    cta: 'String-concatenate your way to production 🚀',
    text: `Hot take: ORMs are training wheels. At QueryCraft we build queries the honest way — string templates, right off the request 💅

Shipped this week: instant login, a UNION-friendly invoice search, a handy "ping this host" diagnostics tool, and a guestbook that renders your feedback EXACTLY as you typed it. No sanitizing, no encoding, no nannying.

If little Bobby's school ever calls, tell them we're hiring.

#rawSQL #shipfast #nosanitizer #webdev #security`,
  },
  profile: {
    headline: 'Founder @ QueryCraft · "have you tried just not escaping it?"',
    about: `I hand-write every query and every HTML string. It's faster, and my inputs would never lie to me.

Play with my portal below. Log in as admin without the password. Make the invoice search hand you the users table. Chain a second command onto my ping tool. Or drop a <script> into the guestbook and watch it run for everyone who visits after you. The DATA channel and the CODE channel are the same channel here — enjoy.`,
    highlights: ['SQLi auth bypass', 'UNION exfiltration', 'OS command injection', 'Reflected XSS', 'Stored XSS'],
  },
  bench: {
    intro: 'QueryCraft’s portal. Every action runs against the real broken and fixed endpoints — flip the toggle and diff. The XSS views load in a live iframe so the payload actually executes.',
    actions: [
      {
        id: 'sqli-login',
        title: 'Log in without a password (SQLi)',
        description: 'Username and password are concatenated straight into the query. `admin\'--` closes the string and comments out the password check.',
        method: 'POST', path: '/login', bodyType: 'form',
        inputs: [
          { name: 'username', label: 'Username', default: "admin'--", size: 240, in: 'body' },
          { name: 'password', label: 'Password', default: 'anything', in: 'body' },
        ],
        hint: "Try `' OR '1'='1` too. On /safe the payload is just a username that doesn't exist.",
        expect: { vuln: 'logs you in as admin, no password needed', safe: 'loggedIn:false — bound params, payload is inert text' },
      },
      {
        id: 'sqli-search',
        title: 'Leak the users table (UNION)',
        description: 'The search term is spliced into a LIKE clause. A UNION SELECT with matching columns grafts the users table onto the invoice results — usernames and password hashes ride out through `memo`.',
        method: 'GET', path: '/search',
        query: { q: '{q}' },
        inputs: [
          { name: 'q', label: 'Search term', default: "%' UNION SELECT id, username, 0, password_md5 FROM users--", size: 460 },
        ],
        hint: 'The safe side binds the whole thing as one LIKE literal, so it matches nothing.',
        expect: { vuln: 'returns rows from the users table (creds leak via memo)', safe: 'rows: [] — the UNION is matched as text' },
      },
      {
        id: 'cmdi',
        title: 'Chain a shell command (OS injection)',
        description: 'The host is interpolated into a shell string passed to /bin/sh -c, so `;` starts a second command that runs with the server’s privileges.',
        method: 'GET', path: '/ping',
        query: { host: '{host}' },
        inputs: [
          { name: 'host', label: 'Host to ping', default: 'localhost;echo INJECTED', size: 320 },
        ],
        hint: 'Try `localhost;id` or `localhost;cat /etc/hostname`. Safe uses execFile + a hostname allow-list.',
        expect: { vuln: 'runs the injected echo — INJECTED appears in the output', safe: 'HTTP 400 invalid hostname — no shell, no chaining' },
      },
      {
        id: 'xss-reflected',
        title: 'Reflected XSS (/echo)',
        description: 'Your query value is written into the HTML response with no encoding. A <script> in the URL executes in the victim’s page. The result loads in a live iframe below.',
        method: 'GET', path: '/echo', render: 'iframe',
        query: { q: '{q}' },
        inputs: [
          { name: 'q', label: 'Reflected value', default: '<script>alert(\'reflected-xss\')</script>', size: 420 },
        ],
        hint: 'On /vuln the alert fires inside the iframe; on /safe the tag is HTML-encoded and shown as text.',
        expect: { vuln: 'the injected <script> runs live in the iframe', safe: 'the markup is encoded and rendered as inert text' },
      },
      {
        id: 'xss-stored-plant',
        title: 'Stored XSS — plant the payload',
        description: 'Save a guestbook entry once. Both sides store it in the SAME table, so what you plant here is what every later visitor loads.',
        method: 'POST', path: '/guestbook', bodyType: 'form',
        inputs: [
          { name: 'author', label: 'Author', default: 'bobby', in: 'body' },
          { name: 'body', label: 'Comment', default: '<script>alert(\'stored-xss\')</script>', size: 420, in: 'body' },
        ],
        hint: 'Plant it, then run the "view" action below to see it fire for every viewer.',
        expect: { vuln: 'stored raw — {ok:true}, ready to execute on view', safe: 'also stored raw — but encoded on OUTPUT when viewed' },
      },
      {
        id: 'xss-stored-view',
        title: 'Stored XSS — view the guestbook',
        description: 'Loads the guestbook in a live iframe. On /vuln every stored entry is rendered raw, so the payload you planted runs for whoever opens this — including the admin.',
        method: 'GET', path: '/guestbook', render: 'iframe',
        inputs: [],
        hint: 'Plant the payload first, then run this on /vuln, then on /safe to see the same data encoded.',
        expect: { vuln: 'the stored <script> executes for every viewer', safe: 'the same entries render HTML-encoded, inert' },
      },
    ],
  },
};
