'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => lab.stop());

const SPRAY = ['123456', 'letmein', 'qwerty', 'password', 'admin', 'welcome'];

describe('A07:2025 Authentication Failures', () => {
  test('password spraying walks straight in — no lockout, no MFA', async () => {
    let cracked = null;
    for (const password of SPRAY) {
      const res = await lab.post('/vuln/a07/login', { json: { username: 'admin', password } });
      if (res.status === 200) { cracked = password; break; }
    }
    assert.equal(cracked, 'admin', 'the default admin credential was never removed');
  });

  test('the same spray never gets in on the fixed endpoint', async () => {
    const statuses = [];
    for (const password of [...SPRAY, ...SPRAY]) {
      const res = await lab.post('/safe/a07/login', { json: { username: 'admin', password } });
      assert.notEqual(res.status, 200, `"${password}" should never yield a session`);
      statuses.push(res.status);
    }
    // 'admin' IS the admin's real password. Rate limiting does not save you
    // from a default credential — the breached-password check does. Both
    // controls have to be present, and they defend against different things.
    assert.ok(statuses.includes(403), 'expected the default credential to be blocked outright');
    assert.ok(statuses.includes(429), 'expected repeated failures to trigger a lockout');
  });

  test('the broken login is a username oracle', async () => {
    const real = await lab.post('/vuln/a07/login', { json: { username: 'alice', password: 'x' } });
    const fake = await lab.post('/vuln/a07/login', { json: { username: 'zzz', password: 'x' } });
    assert.notEqual(real.body.error, fake.body.error, 'demonstrating the leak');
    assert.match(real.body.error, /Incorrect password/);
  });

  test('a correct-but-breached password is blocked and must be rotated', async () => {
    const res = await lab.post('/safe/a07/login', { json: { username: 'alice', password: 'password123' } });
    assert.equal(res.status, 403);
    assert.equal(res.body.mustResetPassword, true);
  });

  test('the fixed login returns one identical message for every failure', async () => {
    const real = await lab.post('/safe/a07/login', { json: { username: 'bob', password: 'x' } });
    const fake = await lab.post('/safe/a07/login', { json: { username: 'zzz', password: 'x' } });
    assert.equal(real.body.error, fake.body.error);
  });

  test('session fixation: the attacker-supplied id survives the login', async () => {
    const planted = 'sess-attacker-controlled';
    const res = await lab.post('/vuln/a07/login', {
      json: { username: 'dana', password: 'trombone-glacier-42-mango' },
      headers: { cookie: `sid=${planted}` },
    });
    assert.equal(res.body.sid, planted, 'the pre-login session is now authenticated as dana');
  });

  test('the fixed login issues a brand new, high-entropy session id', async () => {
    const planted = 'sess-attacker-controlled';
    const res = await lab.post('/safe/a07/login', {
      json: { username: 'dana', password: 'trombone-glacier-42-mango' },
      headers: { cookie: `sid=${planted}` },
    });
    assert.equal(res.status, 200);
    const setCookie = res.headers.getSetCookie().join(';');
    assert.doesNotMatch(setCookie, new RegExp(planted));
    const sid = /sid=([^;]+)/.exec(setCookie)[1];
    assert.ok(sid.length >= 43, 'expected 32 random bytes of session id');
    assert.match(setCookie, /HttpOnly/i);
  });

  test('registration: breached and short passwords are rejected only by the fix', async () => {
    const weak = { username: 'newbie', password: 'qwertyuiop123456' };  // long, but public
    assert.equal((await lab.post('/vuln/a07/register', { json: weak })).status, 200);

    const rejected = await lab.post('/safe/a07/register', { json: weak });
    assert.equal(rejected.status, 400);
    assert.match(rejected.body.error, /breach/);

    const short = await lab.post('/safe/a07/register', { json: { username: 'n', password: 'Sh0rt!' } });
    assert.match(short.body.error, /12 characters/);

    const good = await lab.post('/safe/a07/register', { json: { username: 'n', password: 'trombone-glacier-42-mango' } });
    assert.equal(good.status, 200);
  });
});
