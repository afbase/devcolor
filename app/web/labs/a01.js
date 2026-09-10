'use strict';
// A01:2025 — Broken Access Control (incl. SSRF). Reference front-end module.
// Persona: a proud engineer at a fictional invoicing SaaS. The profile page IS
// the live target — each bench action hits /vuln/a01 and /safe/a01.
module.exports = {
  persona: {
    name: 'Ivan Petrov',
    title: 'Staff Engineer at InvoiceFlow',
    company: 'InvoiceFlow',
    avatar: 'IP',
    color: '#0a66c2',
    banner: 'linear-gradient(120deg,#0b2447,#0a66c2 60%,#378fe9)',
    location: 'Berlin, Germany',
    connections: '4,812',
  },
  post: {
    time: '2h',
    reactions: 214, comments: 47, reposts: 18,
    headline: 'InvoiceFlow: your invoices, one URL away',
    cta: 'Peek at how our access control (doesn’t) hold up',
    summary: `Users can act outside their intended permissions — reading someone else's records by changing an id in the URL, reaching an admin page that was simply never linked, or triggering an action a hidden button was supposed to gate. Server-side requests to an attacker-chosen URL (SSRF) now fall under this category too, since the root cause is the same: nothing on the server confirmed the request was allowed.`,
  },
  profile: {
    headline: 'Staff Engineer @ InvoiceFlow · "we\'ll add auth later"',
    about: `Broken access control means the application fails to enforce what an authenticated user is actually allowed to do. A user can read, modify, or reach data or actions outside their own permissions — often just by changing an id in a URL, guessing an unlinked path, or calling an endpoint the UI never exposed a button for.

Server-side requests made on a user's behalf are held to the same standard: if the destination isn't validated, an attacker can make the server reach internal systems it was never meant to expose (SSRF).

Try it below: read an invoice that isn't yours, walk into the admin list, trigger the "admin-only" action as a regular user, or paste an internal URL into the link previewer and see where the server actually goes.`,
    highlights: ['IDOR', 'Forced browsing', 'Client-side-only checks', 'SSRF (CWE-918)'],
  },
  bench: {
    intro: 'InvoiceFlow’s portal. Every action runs against the real broken and fixed endpoints — run both and diff.',
    actions: [
      {
        id: 'idor',
        title: 'Read an invoice by ID',
        description: 'Fetch an invoice. On /vuln the id from the URL is trusted; on /safe the query is scoped to you.',
        method: 'GET', path: '/invoices/{id}', query: { as: '{who}' },
        inputs: [
          { name: 'id', label: 'Invoice ID', default: '1004' },
          { name: 'who', label: 'Act as', default: 'alice', options: ['alice', 'bob', 'carol', 'admin', 'dana'] },
        ],
        hint: '1004 is Carol’s confidential invoice.',
        code: {
          lang: 'js',
          intro: 'IDOR: the record is fetched by a user-controlled id with no ownership check.',
          vuln: `// /vuln/a01/invoices/:id — the id from the URL is trusted completely
const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?')
  .get(req.params.id);
// Missing "...AND user_id = ?". That single omission is the whole bug.
res.json({ viewer: user.username, invoice });`,
          safe: `// /safe/a01/invoices/:id — ownership is enforced in the query itself
const invoice = db.prepare('SELECT * FROM invoices WHERE id = ? AND user_id = ?')
  .get(req.params.id, req.user.id);
// 404, not 403: a 403 confirms the record exists and leaks the id space.
if (!invoice) return res.status(404).json({ error: 'no such invoice' });
res.json({ viewer: req.user.username, invoice });`,
        },
        expect: { vuln: 'hands you Carol’s SEVERANCE invoice', safe: '404 — you only see your own' },
      },
      {
        id: 'forced',
        title: 'Open the admin user list',
        description: 'A page that simply isn’t linked in the UI. Obscurity is not access control.',
        method: 'GET', path: '/admin/users', query: { as: '{who}' },
        inputs: [{ name: 'who', label: 'Act as', default: 'bob', options: ['bob', 'alice', 'admin'] }],
        code: {
          lang: 'js',
          src: { safe: { anchor: 'const requireRole', to: "safe.get('/admin/users'" } },
          intro: 'Forced browsing: the endpoint enforces nothing; being unlinked is not access control.',
          vuln: `// /vuln/a01/admin/users — the page just isn't linked. That's the only "lock".
vuln.get('/admin/users', (req, res) => {
  res.json({ users: db.prepare('SELECT id, username, email, role FROM users').all() });
});`,
          safe: `// deny-by-default middleware + one reusable, declarative role check
const requireRole = (role) => (req, res, next) =>
  req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });

safe.get('/admin/users', requireRole('admin'), (req, res) => {
  res.json({ users: db.prepare('SELECT id, username, email, role FROM users').all() });
});`,
        },
        expect: { vuln: 'lists every user for anyone', safe: '403 unless you are an admin' },
      },
      {
        id: 'purge',
        title: 'Trigger the “admin-only” purge',
        description: 'The delete button is hidden for non-admins in the UI. curl doesn’t care about hidden buttons.',
        method: 'POST', path: '/invoices/purge', query: { as: '{who}' },
        inputs: [{ name: 'who', label: 'Act as', default: 'bob', options: ['bob', 'alice', 'admin'] }],
        code: {
          lang: 'js',
          intro: 'Client-side-only control: the authorization lives in the UI, not the handler.',
          vuln: `// /vuln/a01/invoices/purge — the UI hides the button; the endpoint never checks the role
vuln.post('/invoices/purge', (req, res) => {
  res.json({ ok: true, wouldHaveDeleted: db.prepare('SELECT COUNT(*) c FROM invoices').get().c });
});`,
          safe: `// the server enforces the role, whatever the UI shows
safe.post('/invoices/purge', requireRole('admin'), (req, res) => {
  res.json({ ok: true, wouldHaveDeleted: db.prepare('SELECT COUNT(*) c FROM invoices').get().c });
});`,
        },
        expect: { vuln: 'runs for anyone', safe: '403 unless admin' },
      },
      {
        id: 'ssrf',
        title: 'Preview a link (SSRF)',
        description: 'The server fetches the URL you paste — from inside the network. Point it at an internal service or the cloud metadata endpoint.',
        method: 'GET', path: '/unfurl', query: { url: '{url}', as: '{who}' },
        inputs: [
          { name: 'url', label: 'URL to preview', default: 'http://internal-api:8081/internal/admin/flag', size: 360 },
          { name: 'who', label: 'Act as', default: 'alice', options: ['alice', 'admin'] },
        ],
        hint: 'Also try http://169.254.169.254/latest/meta-data/iam/security-credentials/lab-role',
        code: {
          lang: 'js',
          intro: 'SSRF (CWE-918): the server makes a request to a user-supplied URL with no allow-list.',
          vuln: `// /vuln/a01/unfurl — the server fetches whatever URL you pass, from inside the network
vuln.all('/unfurl', express.json(), async (req, res) => {
  const target = req.query.url || (req.body && req.body.url);
  const out = await fetchUrl(target);          // no validation at all
  res.json({ fetched: target, ...out });
});`,
          safe: `// validate first: http/https only, and reject hosts that resolve to
// private/loopback/link-local/metadata addresses (resolving beats DNS rebinding)
safe.all('/unfurl', express.json(), async (req, res) => {
  const target = req.query.url || (req.body && req.body.url);
  try {
    const out = await fetchUrl(target, { guard: assertPublicUrl });
    res.json({ fetched: target, ...out });
  } catch (err) {
    res.status(400).json({ error: \`refused to fetch: \${err.message}\` });
  }
});`,
          note: 'The guard lives in app/lib/ssrf-guard.js: it resolves the hostname and blocks private / loopback / link-local / cloud-metadata ranges.',
        },
        expect: { vuln: 'fetches the internal-only service (in Docker)', safe: 'refuses private/loopback/metadata targets' },
      },
    ],
  },
};
