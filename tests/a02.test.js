'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => { lab.stop(); });

describe('A02:2025 Security Misconfiguration', () => {
  test('directory listing leaks a forgotten .env.backup on vuln', async () => {
    const listing = await lab.get('/vuln/a02/files/');
    assert.equal(listing.status, 200);
    assert.match(listing.text, /\.env\.backup/);
    const secret = await lab.get('/vuln/a02/files/.env.backup');
    assert.equal(secret.status, 200);
    assert.match(secret.text, /STRIPE_KEY=sk_live_EXAMPLE/);
    assert.match(secret.text, /DATABASE_URL=postgres:\/\//);
  });

  test('safe: no listing (404), dotfile hidden (404), but brochure still served', async () => {
    assert.equal((await lab.get('/safe/a02/files/')).status, 404);
    assert.equal((await lab.get('/safe/a02/files/.env.backup')).status, 404);
    const brochure = await lab.get('/safe/a02/files/brochure.txt');
    assert.equal(brochure.status, 200);
    assert.match(brochure.text, /brochure/i);
  });

  test('/debug dumps process.env on vuln, does not exist on safe', async () => {
    const dbg = await lab.get('/vuln/a02/debug');
    assert.equal(dbg.status, 200);
    assert.ok(dbg.body.env && Object.keys(dbg.body.env).length > 0);
    assert.equal((await lab.get('/safe/a02/debug')).status, 404);
  });

  test('/boom leaks the stack on vuln, returns an opaque reference on safe', async () => {
    const bad = await lab.get('/vuln/a02/boom');
    assert.equal(bad.status, 500);
    assert.match(bad.text, /at .+:\d+/);                 // a real stack frame
    assert.match(bad.text, /password authentication failed/);

    const good = await lab.get('/safe/a02/boom');
    assert.equal(good.status, 500);
    assert.equal(good.body.error, 'Internal server error');
    assert.match(good.body.reference, /[0-9a-f-]{36}/);  // a reference id, not detail
    assert.doesNotMatch(good.text, /at .+:\d+/);
    assert.doesNotMatch(good.text, /password authentication failed/);
  });

  test('session cookie has security flags only on safe', async () => {
    const v = await lab.get('/vuln/a02/login-demo');
    const vc = v.headers.get('set-cookie') || '';
    assert.match(vc, /demo_session=/);
    assert.doesNotMatch(vc, /HttpOnly/i);
    assert.doesNotMatch(vc, /Secure/i);
    assert.doesNotMatch(vc, /SameSite/i);

    const s = await lab.get('/safe/a02/login-demo');
    const sc = s.headers.get('set-cookie') || '';
    assert.match(sc, /HttpOnly/i);
    assert.match(sc, /Secure/i);
    assert.match(sc, /SameSite=Lax/i);
  });

  test('safe sets baseline security headers and drops the fingerprint', async () => {
    const s = await lab.get('/safe/a02/login-demo');
    assert.ok(s.headers.get('content-security-policy'));
    assert.ok(s.headers.get('strict-transport-security'));
    assert.equal(s.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(s.headers.get('referrer-policy'));
    assert.equal(s.headers.get('x-frame-options'), 'DENY');
    assert.equal(s.headers.get('x-powered-by'), null);

    // The vuln side deliberately advertises itself.
    const v = await lab.get('/vuln/a02/login-demo');
    assert.ok(v.headers.get('x-powered-by'));
  });
});
