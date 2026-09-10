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
    summary: `Code or data is trusted without verifying where it came from — deep-merging arbitrary JSON straight onto internal objects, or applying an "update" with no signature or checksum to confirm it's actually legitimate before it runs.`,
  },
  profile: {
    headline: 'Head of Auto-Updates @ PayloadPipe · "just merge it"',
    about: `Software or data integrity failures happen when code or data is trusted without verifying where it came from or whether it was tampered with — no signature, checksum, or provenance check before it's applied. Deep-merging untrusted JSON onto internal objects, or auto-applying an unsigned "update", both skip the one question that actually matters: did this come from somewhere trustworthy?

Once that check is skipped, anything the attacker can get accepted as input becomes something the system will treat as its own trusted state.

Try it below: sneak a dangerous key past an unfiltered deep-merge, or ship an unsigned "update" and watch it get applied with no verification at all.`,
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
        code: {
          lang: 'js',
          src: { vuln: { anchor: 'function unsafeMerge' } },
          intro: 'The baseline. Both sides accept known keys — but look at HOW each one merges input.',
          vuln: `// unsafe deep-merge: walks every key and recurses on objects, with bracket access on the target
function unsafeMerge(target, source) {
  for (const key in source) {
    const value = source[key];
    if (value && typeof value === 'object') {
      if (typeof target[key] !== 'object' || target[key] === null) target[key] = {};
      unsafeMerge(target[key], value);   // for key "__proto__", target[key] IS Object.prototype
    } else target[key] = value;
  }
  return target;
}`,
          safe: `// allow-list onto a null-prototype object → there is no prototype to pollute
const prefs = Object.assign(Object.create(null), PREFERENCE_DEFAULTS);
for (const key of Object.keys(input)) {
  if (ALLOWED_PREFS.has(key)) prefs[key] = input[key];   // unknown keys never make it in
}`,
        },
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
        code: {
          lang: 'js',
          src: { safe: { anchor: 'const FORBIDDEN_KEYS', to: "safe.post('/preferences'" } },
          intro: 'Prototype pollution: a nested __proto__ key walks into Object.prototype and poisons every object.',
          vuln: `// POST {"__proto__":{"isAdmin":true}} → unsafeMerge writes onto Object.prototype
const merged = unsafeMerge({ ...PREFERENCE_DEFAULTS }, req.body || {});
// a brand-new object that NEVER touched the request now inherits the attacker's keys:
const bystander = {};
bystander.isAdmin;   // → true`,
          safe: `// refuse the dangerous keys outright (clearer than silently dropping; shows up in logs)
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
for (const key of Object.keys(input))
  if (FORBIDDEN_KEYS.has(key))
    return res.status(400).json({ error: \`refused dangerous key: \${key}\` });`,
        },
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
        code: {
          lang: 'js',
          intro: 'Integrity failure: applying an update whose origin was never verified (CWE-345).',
          vuln: `// applies any {name, payload} that arrives — no signature, no checksum, no provenance
const { name, payload } = req.body || {};
res.json({ applied: true, name, payload });`,
          safe: `// require a valid HMAC signature over the payload; constant-time compare
if (!signature) return res.status(400).json({ error: 'unsigned update rejected' });
const expected = signPayload(payload);            // HMAC-SHA256 over canonical JSON
const got = Buffer.from(String(signature)), want = Buffer.from(expected);
if (got.length !== want.length || !crypto.timingSafeEqual(got, want))
  return res.status(400).json({ error: 'signature verification failed' });`,
        },
        expect: {
          vuln: 'applied: true — runs your payload, no provenance',
          safe: '400 — unsigned update rejected',
        },
      },
    ],
  },
};
