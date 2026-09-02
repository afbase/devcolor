'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => lab.stop());

describe('A05:2025 Injection', () => {
  test('SQLi: comment-out payload logs in as admin with no password', async () => {
    const res = await lab.post('/vuln/a05/login', { form: { username: "admin'--", password: 'wrong' } });
    assert.equal(res.body.loggedIn, true);
    assert.equal(res.body.user.username, 'admin');
  });

  test('SQLi: parameterised query treats the payload as a literal username', async () => {
    const res = await lab.post('/safe/a05/login', { form: { username: "admin'--", password: 'wrong' } });
    assert.equal(res.body.loggedIn, false);
  });

  test('the fixed login still works for real credentials', async () => {
    const res = await lab.post('/safe/a05/login', { form: { username: 'alice', password: 'password123' } });
    assert.equal(res.body.loggedIn, true);
  });

  test('SQLi: UNION payload exfiltrates the password hashes', async () => {
    const q = encodeURIComponent("x' UNION SELECT id, username, password_md5, 0 FROM users--");
    const res = await lab.get(`/vuln/a05/search?q=${q}`);
    assert.equal(res.status, 200);
    const names = res.body.rows.map((r) => r.memo);
    assert.ok(names.includes('admin'), 'expected usernames to leak through the UNION');
  });

  test('SQLi: the fixed search binds the term and finds nothing', async () => {
    const q = encodeURIComponent("x' UNION SELECT id, username, password_md5, 0 FROM users--");
    const res = await lab.get(`/safe/a05/search?q=${q}`);
    assert.deepEqual(res.body.rows, []);
  });

  test('command injection: a semicolon runs a second shell command', async () => {
    const res = await lab.get('/vuln/a05/ping?host=localhost;echo INJECTED');
    assert.match(res.text, /INJECTED/);
  });

  test('command injection: execFile + allow-list rejects the payload', async () => {
    const res = await lab.get('/safe/a05/ping?host=localhost;echo INJECTED');
    assert.equal(res.status, 400);
    assert.doesNotMatch(res.text, /INJECTED/);
  });

  test('XSS: the broken echo reflects a live script tag', async () => {
    const res = await lab.get('/vuln/a05/echo?q=<script>alert(1)</script>');
    assert.match(res.text, /<script>alert\(1\)<\/script>/);
  });

  test('XSS: the fixed echo encodes the angle brackets', async () => {
    const res = await lab.get('/safe/a05/echo?q=<script>alert(1)</script>');
    assert.doesNotMatch(res.text, /<script>alert/);
    assert.match(res.text, /&lt;script&gt;/);
  });

  test('XSS: the fixed echo also sends a Content-Security-Policy', async () => {
    const res = await lab.get('/safe/a05/echo?q=hello');
    assert.match(res.headers.get('content-security-policy') || '', /script-src/);
  });

  test('stored XSS: a payload saved once renders raw for every later viewer', async () => {
    // Post the payload through the VULN guestbook...
    const post = await lab.post('/vuln/a05/guestbook', { form: { author: 'mallory', body: '<script>alert(1)</script>' } });
    assert.equal(post.body.ok, true);
    // ...and it comes back live in the rendered page — this is the stored bug.
    const page = await lab.get('/vuln/a05/guestbook');
    assert.match(page.text, /<script>alert\(1\)<\/script>/);
  });

  test('stored XSS: the fixed guestbook encodes the stored payload on output', async () => {
    // The same table (the payload above is already stored). The safe renderer
    // encodes it, so the browser shows text instead of executing a script.
    const page = await lab.get('/safe/a05/guestbook');
    assert.doesNotMatch(page.text, /<script>alert\(1\)<\/script>/);
    assert.match(page.text, /&lt;script&gt;/);
    assert.match(page.headers.get('content-security-policy') || '', /script-src/);
  });
});
