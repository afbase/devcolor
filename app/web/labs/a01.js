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
    text: `Big week at InvoiceFlow 🎉 We shipped our new customer invoice portal — clean URLs like /invoices/1001, an admin console, and a slick "unfurl this link" preview for webhooks.

"Move fast" is our motto. We'll add the authorization checks later 😅

#shipit #webdev #security #startuplife`,
  },
  profile: {
    headline: 'Staff Engineer @ InvoiceFlow · "we\'ll add auth later"',
    about: `I build fast. InvoiceFlow lets customers view invoices by ID, browse the admin console, and preview any webhook URL.

Try my portal below. Read an invoice that isn't yours. Walk into the admin list. Or paste an internal URL into the link previewer and see where it goes — our server has opinions your browser doesn't.`,
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
        expect: { vuln: 'hands you Carol’s SEVERANCE invoice', safe: '404 — you only see your own' },
      },
      {
        id: 'forced',
        title: 'Open the admin user list',
        description: 'A page that simply isn’t linked in the UI. Obscurity is not access control.',
        method: 'GET', path: '/admin/users', query: { as: '{who}' },
        inputs: [{ name: 'who', label: 'Act as', default: 'bob', options: ['bob', 'alice', 'admin'] }],
        expect: { vuln: 'lists every user for anyone', safe: '403 unless you are an admin' },
      },
      {
        id: 'purge',
        title: 'Trigger the “admin-only” purge',
        description: 'The delete button is hidden for non-admins in the UI. curl doesn’t care about hidden buttons.',
        method: 'POST', path: '/invoices/purge', query: { as: '{who}' },
        inputs: [{ name: 'who', label: 'Act as', default: 'bob', options: ['bob', 'alice', 'admin'] }],
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
        expect: { vuln: 'fetches the internal-only service (in Docker)', safe: 'refuses private/loopback/metadata targets' },
      },
    ],
  },
};
