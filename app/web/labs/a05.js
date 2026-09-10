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
    summary: `Untrusted input gets interpreted as code by a downstream interpreter — SQL, an OS shell, or a browser's HTML parser. String-built queries and unescaped output let user-supplied data become commands: bypassing a login, exfiltrating a whole table, or running a script in someone else's browser session.`,
  },
  profile: {
    headline: 'Founder @ QueryCraft · "have you tried just not escaping it?"',
    about: `Injection happens when untrusted input reaches an interpreter — a SQL engine, an OS shell, or a browser's HTML/JS parser — without being kept separate from the commands or structure it's inserted into. The interpreter can't tell attacker-supplied data apart from instructions, so that input ends up executing as part of the query, the command, or the page itself.

The same root cause shows up in very different-looking bugs: a login bypass, a data leak, and a script running in someone else's browser can all trace back to one missing boundary between data and code.

Try it below: log in as admin without a password, make an invoice search hand you the entire users table, chain a second command onto a diagnostics tool, or drop a script into a guestbook and watch it execute for the next visitor.`,
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
        code: {
          lang: 'js',
          intro: 'SQL injection: string-concatenated input becomes part of the query grammar.',
          vuln: `// username + password concatenated straight into the query text
const sql = \`SELECT * FROM users WHERE username='\${u}' AND password_md5='\${md5(p)}'\`;
const user = db.prepare(sql).get();
// admin'--  closes the string and comments out the password check`,
          safe: `// bound parameters keep input in the DATA channel; the driver never re-parses it as SQL
const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?')
  .get(u, md5(p));
// admin'--  is now just a username that doesn't exist`,
        },
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
        code: {
          lang: 'js',
          intro: 'UNION-based exfiltration: unparameterized input can append a query that reads another table.',
          vuln: `// the term is spliced into a LIKE clause → a UNION SELECT grafts on another table
const sql = \`SELECT id, memo, amount_cents, user_id FROM invoices WHERE memo LIKE '%\${q}%'\`;
const rows = db.prepare(sql).all();
// %' UNION SELECT id, username, 0, password_md5 FROM users--  leaks creds via memo`,
          safe: `// the whole term is bound as one LIKE literal — a UNION payload is matched as text
const rows = db.prepare('SELECT id, user_id, amount_cents, memo FROM invoices WHERE memo LIKE ?')
  .all(\`%\${q}%\`);`,
        },
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
        code: {
          lang: 'js',
          intro: 'OS command injection: building a shell string lets `;` start a second command.',
          vuln: `// host interpolated into a shell string → exec() spawns /bin/sh -c, so \`;\` chains a command
exec(\`ping -c 1 \${host}\`, { timeout: 3000 }, (err, stdout, stderr) => {
  res.type('text/plain').send(\`\${stdout || ''}\${stderr || ''}\${err ? err.message : ''}\`);
});`,
          safe: `// no shell: execFile passes argv directly to the binary. Plus a positive allow-list.
const HOSTNAME = /^[a-zA-Z0-9.-]+$/;
if (!HOSTNAME.test(host)) return res.status(400).type('text/plain').send('invalid hostname');
execFile('ping', ['-c', '1', host], { timeout: 3000 }, (err, stdout, stderr) => { /* ... */ });`,
        },
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
        code: {
          lang: 'js',
          intro: 'Reflected XSS: user input echoed into HTML without output encoding.',
          vuln: `// the query value is written into the HTML response with no encoding
res.type('html').send(\`<!doctype html><body><p>You searched for: \${q}</p></body>\`);
// ?q=<script>alert(1)</script>  executes in the victim's page`,
          safe: `// encode for the HTML text-node context before writing (+ a CSP as defence-in-depth)
withCsp(res).type('html')
  .send(\`<!doctype html><body><p>You searched for: \${escapeHtml(q)}</p></body>\`);`,
        },
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
        code: {
          lang: 'js',
          intro: 'Stored XSS is planted here; whether it fires is decided when the entry is rendered.',
          vuln: `// stored raw — the payload persists and will run for every later viewer
db.prepare('INSERT INTO guestbook (author, body) VALUES (?, ?)').run(author, body);
res.json({ ok: true });`,
          safe: `// the SAFE side ALSO stores raw — storing raw is fine; the fix is to encode on OUTPUT
db.prepare('INSERT INTO guestbook (author, body) VALUES (?, ?)').run(author, body);
res.json({ ok: true });   // see "view the guestbook" for where the encoding happens`,
        },
        expect: { vuln: 'stored raw — {ok:true}, ready to execute on view', safe: 'also stored raw — but encoded on OUTPUT when viewed' },
      },
      {
        id: 'xss-stored-view',
        title: 'Stored XSS — view the guestbook',
        description: 'Loads the guestbook in a live iframe. On /vuln every stored entry is rendered raw, so the payload you planted runs for whoever opens this — including the admin.',
        method: 'GET', path: '/guestbook', render: 'iframe',
        inputs: [],
        hint: 'Plant the payload first, then run this on /vuln, then on /safe to see the same data encoded.',
        code: {
          lang: 'js',
          intro: 'Stored XSS fires on output: encode when you render, not (only) when you store.',
          vuln: `// renders every stored entry RAW → the planted <script> executes for whoever opens it
const rows = db.prepare('SELECT author, body FROM guestbook ORDER BY id').all();
res.type('html').send(renderGuestbook(rows, { encode: false }));   // raw — the bug`,
          safe: `// same data, encoded on output → the markup renders as inert text
withCsp(res).type('html').send(renderGuestbook(rows, { encode: true }));   // encoded — the fix
// renderGuestbook runs each field through escapeHtml when encode:true`,
        },
        expect: { vuln: 'the stored <script> executes for every viewer', safe: 'the same entries render HTML-encoded, inert' },
      },
    ],
  },
};
