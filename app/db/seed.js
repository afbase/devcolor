'use strict';
const crypto = require('node:crypto');

/** A04: the WRONG way to store a password — unsalted, fast, GPU-friendly. */
function md5(plaintext) {
  return crypto.createHash('md5').update(plaintext).digest('hex');
}
/** A04: the RIGHT way — random salt + a deliberately slow KDF, stored together. */
function scryptHash(plaintext) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(plaintext, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('hex')}$${derived.toString('hex')}`;
}
/** Constant-time verification against the scrypt format above. */
function scryptVerify(plaintext, stored) {
  const [scheme, N, r, p, saltHex, hashHex] = String(stored).split('$');
  if (scheme !== 'scrypt') return false;
  const derived = crypto.scryptSync(plaintext, Buffer.from(saltHex, 'hex'), 32, {
    N: Number(N), r: Number(r), p: Number(p),
  });
  const expected = Buffer.from(hashHex, 'hex');
  if (expected.length !== derived.length) return false;
  return crypto.timingSafeEqual(expected, derived);
}

/**
 * Populate an already-migrated database with a small, realistic data set.
 * Idempotent: if users already exist (the file-backed Docker DB), it no-ops.
 */
function seed(db) {
  if (db.prepare('SELECT COUNT(*) AS c FROM users').get().c > 0) return { seeded: false };

  const insertUser = db.prepare(`INSERT INTO users
    (id, username, email, full_name, role, password_md5, password_scrypt, mfa_enabled)
    VALUES (@id, @username, @email, @full_name, @role, @md5, @scrypt, @mfa)`);
  const people = [
    { id: 1, username: 'alice',  email: 'alice@acme.example',  full_name: 'Alice Nguyen',  role: 'user',   pw: 'password123',                 mfa: 0 },
    { id: 2, username: 'bob',    email: 'bob@acme.example',    full_name: 'Bob Carter',    role: 'user',   pw: 'hunter2',                     mfa: 0 },
    { id: 3, username: 'carol',  email: 'carol@acme.example',  full_name: 'Carol Diaz',    role: 'user',   pw: 'correct horse battery staple',mfa: 1 },
    // A02 / A07: a default admin account nobody remembered to remove.
    { id: 4, username: 'admin',  email: 'admin@acme.example',  full_name: 'Site Admin',    role: 'admin',  pw: 'admin',                       mfa: 0 },
    // The only account with a password that is long AND not in a wordlist.
    { id: 5, username: 'dana',   email: 'dana@acme.example',   full_name: 'Dana Osei',     role: 'user',   pw: 'trombone-glacier-42-mango',   mfa: 1 },
    // A support agent who reads customer tickets in the admin console (A05 stored XSS victim).
    { id: 6, username: 'agent',  email: 'agent@acme.example',  full_name: 'Support Agent', role: 'agent',  pw: 'summer-lantern-goose-19',     mfa: 1 },
  ];
  const insertMany = db.transaction((rows) => {
    for (const u of rows) {
      insertUser.run({ ...u, md5: md5(u.pw), scrypt: scryptHash(u.pw) });
    }
  });
  insertMany(people);

  const acct = db.prepare('INSERT INTO accounts (user_id, balance_cents) VALUES (?, ?)');
  for (const uid of [1, 2, 3, 5]) acct.run(uid, 50000);

  const inv = db.prepare('INSERT INTO invoices (id, user_id, amount_cents, memo) VALUES (?, ?, ?, ?)');
  inv.run(1001, 1, 4200,  'Alice — laptop stand');
  inv.run(1002, 1, 15000, 'Alice — conference ticket');
  inv.run(1003, 2, 899,   'Bob — coffee');
  inv.run(1004, 3, 99900, 'Carol — SEVERANCE PAYMENT (confidential)');
  inv.run(1005, 5, 6400,  'Dana — standing desk');

  db.prepare('INSERT INTO coupons (code, percent_off, max_uses) VALUES (?, ?, ?)').run('WELCOME10', 10, 1);
  db.prepare('INSERT INTO coupons (code, percent_off, max_uses) VALUES (?, ?, ?)').run('LOYAL25', 25, 3);

  const gb = db.prepare('INSERT INTO guestbook (author, body) VALUES (?, ?)');
  gb.run('alice', 'First! Loving the new dashboard.');
  gb.run('bob', 'Anyone know how to export invoices to CSV?');

  const tix = db.prepare('INSERT INTO support_tickets (user_id, subject, body, status) VALUES (?, ?, ?, ?)');
  tix.run(2, 'Cannot download my receipt', 'The PDF button spins forever on Safari.', 'open');
  tix.run(1, 'Change billing email', 'Please update my billing email to alice.new@acme.example.', 'open');

  const wh = db.prepare('INSERT INTO webhooks (user_id, label, target_url) VALUES (?, ?, ?)');
  wh.run(1, 'Slack notifier', 'https://hooks.slack.example/T000/B000/xxxx');

  return { seeded: true, users: people.length };
}

module.exports = { seed, md5, scryptHash, scryptVerify };
