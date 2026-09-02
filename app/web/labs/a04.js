'use strict';
// A04:2025 — Cryptographic Failures. The failures got more basic, not more
// exotic: predictable tokens from Math.random(), serving unsalted MD5 password
// material, and encrypting without authenticating (AES-CBC, static IV, no tag).
// The persona is a "rolled our own crypto" enthusiast who is very proud of it.
module.exports = {
  persona: {
    name: 'Marlowe Cipher',
    title: 'Chief Cryptography Officer at VaultBro',
    company: 'VaultBro',
    avatar: 'MC',
    color: '#0e7490',
    banner: 'linear-gradient(120deg,#083344,#0e7490 60%,#22d3ee)',
    location: 'Zug, Switzerland',
    connections: '6,270',
  },
  post: {
    time: '3h',
    reactions: 128, comments: 91, reposts: 12,
    headline: 'VaultBro: cryptography, but make it fast ⚡',
    cta: 'Guess a reset token before it expires',
    text: `Hot take from the VaultBro lab 🔐 We built our own crypto stack because the standard libraries are honestly overkill.

Our password-reset tokens? Generated instantly with Math.random() — plenty random for me. Our encryption? Classic AES, nice and speedy, none of that "authentication tag" overhead slowing us down. And we hash passwords with good old MD5 because it's blazingly fast. Speed IS a feature.

A "researcher" DMed me saying our tokens are predictable. Jealous, probably.

#cryptography #infosec #performance #rollyourown #trustme`,
  },
  profile: {
    headline: 'Chief Cryptography Officer @ VaultBro · "we rolled our own"',
    about: `I do cryptography the fast way. VaultBro mints reset tokens with Math.random(), hashes with MD5 because speed, and encrypts with plain AES-CBC — who needs an auth tag?

Break it on the bench. Pull a reset-token a few times and watch how guessable it is. Ask for the password hashes and crack them in your head. Seal a payload, flip a byte of the ciphertext, and unseal it — no key required. Then flip to Fixed: CSPRNG tokens, a 403 where the hashes used to be, a constant-time verify, and AES-GCM that throws the moment you tamper.`,
    highlights: ['Predictable tokens (Math.random)', 'Unsalted MD5 hashes', 'Exposed password material', 'AES-CBC bit-flipping', 'Static IV', 'No authentication tag'],
  },
  bench: {
    intro: 'VaultBro\'s "artisanal" crypto vs the boring correct version. Run each action a few times and diff.',
    actions: [
      {
        id: 'reset-token',
        title: 'Pull a password-reset token',
        description: 'Run this several times on each side. The vuln token is short base36 from Math.random() (not a CSPRNG); the safe one is 32 CSPRNG bytes.',
        method: 'GET', path: '/reset-token',
        hint: 'Hit "Run" repeatedly — the vuln tokens are short and correlated; the safe ones are 43 unguessable chars.',
        expect: { vuln: '≤8 chars of guessable base36 from Math.random()', safe: '43-char base64url from crypto.randomBytes(32)' },
      },
      {
        id: 'password-hashes',
        title: 'Ask for the password hashes',
        description: 'Even "just the hashes" is a breach when they are unsalted MD5 — a wordlist cracks them in milliseconds. The safe side refuses outright.',
        method: 'GET', path: '/password-hashes',
        hint: 'md5(\'admin\') === 21232f297a57a5a743894a0e4a801fc3.',
        expect: { vuln: 'returns every username + unsalted MD5 hash', safe: '403 — password material is never served' },
      },
      {
        id: 'verify-password',
        title: 'Verify a password (safe side only)',
        description: 'The correct pattern: verification happens server-side against a slow salted scrypt hash, in constant time, and only ever returns a boolean. There is no vulnerable version of this — it exists only on /safe.',
        method: 'POST', path: '/verify-password', sides: ['safe'],
        inputs: [
          { name: 'username', label: 'Username', default: 'admin' },
          { name: 'password', label: 'Password', default: 'admin', in: 'body' },
        ],
        body: { username: '{username}' },
        hint: 'Try the right and wrong password — same timing either way (a decoy hash covers the "no such user" path).',
        expect: { safe: '{ ok: true|false } and nothing else — no hash, no timing leak' },
      },
      {
        id: 'seal',
        title: 'Seal a payload',
        description: 'Encrypt some data. The vuln side is AES-CBC with a static all-zero IV and no tag; the safe side is AES-GCM with a fresh random IV and an auth tag.',
        method: 'GET', path: '/seal', query: { data: '{data}' },
        inputs: [{ name: 'data', label: 'Plaintext', default: 'role:user', size: 320 }],
        hint: 'Copy the vuln ciphertext, flip a byte, and unseal it below — no key needed.',
        expect: { vuln: 'returns ciphertext only — nothing binds the bytes', safe: 'returns iv + ciphertext + tag' },
      },
      {
        id: 'unseal',
        title: 'Unseal (and try tampering)',
        description: 'Decrypt a ciphertext. On vuln, a bit-flipped ciphertext still decrypts to attacker-chosen bytes. On safe, any tampering fails the GCM tag check and is rejected.',
        method: 'GET', path: '/unseal', query: { ciphertext: '{ciphertext}', iv: '{iv}', tag: '{tag}' },
        inputs: [
          { name: 'ciphertext', label: 'Ciphertext (hex)', default: '', size: 360 },
          { name: 'iv', label: 'IV (hex, safe only)', default: '' },
          { name: 'tag', label: 'Tag (hex, safe only)', default: '' },
        ],
        hint: 'Seal above first, paste the ciphertext here. For safe, paste iv + tag too.',
        expect: { vuln: 'decrypts anything, including a rewritten plaintext', safe: 'rejects tampered input — integrity check failed' },
      },
    ],
  },
};
