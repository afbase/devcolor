'use strict';
// A08:2025 — Software or Data Integrity Failures. Front-end module.
// Persona: an over-eager "supply chain" evangelist who trusts every payload
// that shows up. The profile page IS the live target — each bench action hits
// /vuln/a08 and /safe/a08 (see app/routes/a08-integrity-failures.js).
module.exports = {
  persona: {
    name: 'Trusty McMerge',
    title: 'Head of Auto-Updates at PayloadPipe',
    company: 'PayloadPipe',
    avatar: 'TM',
    color: '#8e44ad',
    banner: 'linear-gradient(120deg,#2c0b3f,#8e44ad 55%,#c39bd3)',
    location: 'Continuous Deployment, CI/CD',
    connections: '3,141',
  },
  post: {
    time: '3h',
    reactions: 172, comments: 63, reposts: 29,
    headline: 'PayloadPipe: if it POSTs, we trust it',
    cta: 'Merge any JSON, apply any update — no questions asked',
    text: `Thrilled to announce PayloadPipe 🚀 Our preferences service deep-merges whatever JSON you send straight onto our defaults — so flexible! And our auto-update channel applies any {name, payload} the instant it arrives. ⚡

Signatures? Checksums? Provenance? That's friction, and we are a FRICTIONLESS org. If the request made it to my server, clearly it's legit. 😌

#devops #supplychain #shipfast #trustme #integrityisavibe`,
  },
  profile: {
    headline: 'Head of Auto-Updates @ PayloadPipe · "just merge it"',
    about: `I never met a payload I didn't trust. Send my preferences endpoint some JSON and I'll recursively merge it onto my objects — every key, no filtering. Push an "update" to my apply-update channel and I'll run it without ever checking who signed it.

Play with my services below. Sneak a dangerous key past my deep-merge, or ship me an unsigned "update" and watch me apply it. The fixed side keeps an allow-list and demands a valid HMAC signature — the whole point of integrity.`,
    highlights: ['Prototype pollution', 'Unsafe deep-merge', 'Unsigned updates', 'No provenance (CWE-345)'],
  },
  bench: {
    intro: 'PayloadPipe’s integrity-free services. Run each action on /vuln (trusts anything) and /safe (allow-list + signature) and diff. For the full prototype-pollution pop, use the curl in the hint — a browser form can’t send a nested __proto__ key.',
    actions: [
      {
        id: 'prefs-normal',
        title: 'Set your preferences (baseline)',
        description: 'A harmless preferences update. Both sides accept known keys — this is what "working" looks like before you attack it.',
        method: 'POST', path: '/preferences',
        inputs: [
          { name: 'theme', label: 'theme', default: 'dark', in: 'body' },
          { name: 'pageSize', label: 'pageSize', default: '50', in: 'body' },
        ],
        expect: {
          vuln: 'merges your prefs; bystander object is (for now) clean',
          safe: 'copies only allow-listed keys onto a null-prototype object',
        },
      },
      {
        id: 'prefs-pollute',
        title: 'Poison every object with __proto__',
        description: 'Send a nested __proto__ in the preferences body. The vuln deep-merge walks it and writes onto Object.prototype, so a brand-new unrelated object suddenly has isAdmin. The fixed side refuses __proto__ / constructor / prototype outright. Edit the payload and run both sides.',
        method: 'POST', path: '/preferences',
        // Real pollution vector, driven straight from the form.
        rawBody: '{"__proto__": {"isAdmin": {isAdmin}, "role": "{role}"}, "theme": "{theme}"}',
        inputs: [
          { name: 'isAdmin', label: 'inject isAdmin', default: 'true', options: ['true', 'false'] },
          { name: 'role', label: 'inject role', default: 'admin' },
          { name: 'theme', label: 'theme (legit key)', default: 'dark' },
        ],
        hint: 'Watch pollutedBystanderObject — that object was never in the merge.',
        expect: {
          vuln: 'pollutedBystanderObject.isAdmin becomes true (200)',
          safe: '400 — refused dangerous key; bystander stays clean',
        },
      },
      {
        id: 'apply-update',
        title: 'Ship an unsigned "auto-update"',
        description: 'Push a {name, payload} to the update channel. The vuln side applies anything that arrives; the fixed side rejects it because there is no valid HMAC signature to prove where it came from.',
        method: 'POST', path: '/apply-update',
        inputs: [
          { name: 'name', label: 'update name', default: 'billing-plugin@evil', in: 'body' },
          { name: 'payload', label: 'payload', default: 'rm -rf / # totally legit patch', in: 'body', size: 360 },
        ],
        expect: {
          vuln: 'applied: true — runs your payload, no provenance',
          safe: '400 — unsigned update rejected',
        },
      },
    ],
  },
};
