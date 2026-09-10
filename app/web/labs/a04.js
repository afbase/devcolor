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
    summary: `Sensitive data protected with weak or misused cryptography: predictable tokens from an insecure random number generator, fast unsalted hashes used for passwords, and encryption without authentication that lets ciphertext be tampered with and go completely undetected.`,
  },
  profile: {
    headline: 'Chief Cryptography Officer @ VaultBro · "we rolled our own"',
    about: `Cryptographic failures happen when sensitive data is protected with weak, outdated, or misused cryptography rather than with nothing at all — which can be more dangerous, because it looks secure. Predictable random number generators, unsalted fast hashes, and encryption without integrity checking each give an attacker a practical way to forge, crack, or tamper with data that was supposed to be protected.

The pattern to notice: cryptography that is merely present isn't the same as cryptography that's actually sound.

Try it below: pull a password-reset token a few times and watch how guessable it is, ask for the password hashes and see how fast they crack, then seal a payload, flip a single byte of the ciphertext, and unseal it again with no key required.`,
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
        code: {
          lang: 'js',
          intro: 'Predictable tokens: Math.random() is not cryptographically secure.',
          vuln: `// Math.random() is NOT a CSPRNG: short, low-entropy, predictable from a few samples
const token = Math.random().toString(36).slice(2, 10);   // ≤ 8 chars of guessable base36
res.json({ token });`,
          safe: `// a CSPRNG: 32 random bytes, URL-safe → ~256 bits of entropy, unguessable
const token = crypto.randomBytes(32).toString('base64url');   // 43 chars
res.json({ token });`,
        },
        expect: { vuln: '≤8 chars of guessable base36 from Math.random()', safe: '43-char base64url from crypto.randomBytes(32)' },
      },
      {
        id: 'password-hashes',
        title: 'Ask for the password hashes',
        description: 'Even "just the hashes" is a breach when they are unsalted MD5 — a wordlist cracks them in milliseconds. The safe side refuses outright.',
        method: 'GET', path: '/password-hashes',
        hint: 'md5(\'admin\') === 21232f297a57a5a743894a0e4a801fc3.',
        code: {
          lang: 'js',
          intro: 'Exposing hashes at all is a breach — doubly so when they are fast, unsalted MD5.',
          vuln: `// returns password material — and it's unsalted MD5, cracked by a wordlist in ms
const rows = db.prepare('SELECT username, password_md5 FROM users').all();
res.json({ rows });`,
          safe: `// password material is NEVER served; verification happens server-side only
res.status(403).json({ error: 'password material is never served' });`,
        },
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
        code: {
          lang: 'js',
          intro: 'The correct pattern — there is no vulnerable version. Slow salted KDF, constant time, boolean out.',
          safeLabel: '🔒 Fixed — the only version that exists',
          safe: `const user = db.prepare('SELECT password_scrypt FROM users WHERE username = ?').get(username);
// Always run scryptVerify (against a decoy when there's no such user) so the work —
// and therefore the timing — is the same whether or not the user exists.
const stored = user ? user.password_scrypt : DECOY_SCRYPT;
const ok = scryptVerify(String(password), stored) && Boolean(user);
res.json({ ok });   // a boolean, and nothing else`,
        },
        expect: { safe: '{ ok: true|false } and nothing else — no hash, no timing leak' },
      },
      {
        id: 'seal',
        title: 'Seal a payload',
        description: 'Encrypt some data. The vuln side is AES-CBC with a static all-zero IV and no tag; the safe side is AES-GCM with a fresh random IV and an auth tag.',
        method: 'GET', path: '/seal', query: { data: '{data}' },
        inputs: [{ name: 'data', label: 'Plaintext', default: 'role:user', size: 320 }],
        hint: 'Copy the vuln ciphertext, flip a byte, and unseal it below — no key needed.',
        code: {
          lang: 'js',
          intro: 'Encrypting without authenticating: CBC hides data but lets an attacker rewrite it (bit-flipping).',
          vuln: `// AES-256-CBC with a STATIC all-zero IV and NO auth tag → confidentiality without integrity
const STATIC_IV = Buffer.alloc(16, 0);
const cipher = crypto.createCipheriv('aes-256-cbc', KEY, STATIC_IV);
const ct = Buffer.concat([cipher.update(String(data), 'utf8'), cipher.final()]);
res.json({ ciphertext: ct.toString('hex') });   // nothing binds the bytes`,
          safe: `// AES-256-GCM: a fresh random IV every time + an authentication tag (encrypt-then-MAC)
const iv = crypto.randomBytes(12);   // never reused with this key
const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
const ct = Buffer.concat([cipher.update(String(data), 'utf8'), cipher.final()]);
res.json({ iv: iv.toString('hex'), ciphertext: ct.toString('hex'), tag: cipher.getAuthTag().toString('hex') });`,
        },
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
        code: {
          lang: 'js',
          intro: 'Without an auth tag, tampered ciphertext still "decrypts" — GCM rejects it instead.',
          vuln: `// decrypts whatever you send — including a bit-flipped ciphertext that decrypts to
// attacker-chosen bytes (CBC malleability), because nothing verifies integrity
const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, STATIC_IV);
const pt = Buffer.concat([decipher.update(Buffer.from(hex, 'hex')), decipher.final()]);
res.json({ plaintext: pt.toString('utf8') });`,
          safe: `// GCM verifies the tag on decrypt; any tampered byte makes final() throw
try {
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  const pt = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]);
  res.json({ plaintext: pt.toString('utf8') });
} catch (err) {
  res.status(400).json({ error: 'integrity check failed' });   // reject, don't guess
}`,
        },
        expect: { vuln: 'decrypts anything, including a rewritten plaintext', safe: 'rejects tampered input — integrity check failed' },
      },
    ],
  },
};
