'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab, startInternalService } = require('./helpers');

const lab = startLab();
const internal = startInternalService();
after(() => { lab.stop(); internal.stop(); });

describe('A01:2025 Broken Access Control', () => {
  test('IDOR: the broken endpoint hands Alice someone else\'s invoice', async () => {
    const res = await lab.get('/vuln/a01/invoices/1004?as=alice');
    assert.equal(res.status, 200);
    assert.match(res.body.invoice.memo, /SEVERANCE/);
    assert.equal(res.body.invoice.user_id, 3);
  });

  test('IDOR: the fixed endpoint scopes the query to the caller (404, not 403)', async () => {
    const res = await lab.get('/safe/a01/invoices/1004?as=alice');
    assert.equal(res.status, 404);
    const mine = await lab.get('/safe/a01/invoices/1001?as=alice');
    assert.equal(mine.status, 200);
    assert.equal(mine.body.invoice.user_id, 1);
  });

  test('forced browsing: /admin/users is open on vuln, role-checked on safe', async () => {
    assert.equal((await lab.get('/vuln/a01/admin/users?as=bob')).status, 200);
    assert.equal((await lab.get('/safe/a01/admin/users?as=bob')).status, 403);
    assert.equal((await lab.get('/safe/a01/admin/users?as=admin')).status, 200);
  });

  test('client-side-only control: curl ignores the hidden button', async () => {
    assert.equal((await lab.post('/vuln/a01/invoices/purge?as=bob')).status, 200);
    assert.equal((await lab.post('/safe/a01/invoices/purge?as=bob')).status, 403);
  });

  test('deny by default: no identity means no access', async () => {
    assert.equal((await lab.get('/safe/a01/invoices/1001?as=ghost')).status, 401);
  });

  test('SSRF: the vulnerable unfurl reaches an internal-only service', async () => {
    const target = `${await internal.url()}/internal/admin/flag`;
    const res = await lab.get(`/vuln/a01/unfurl?url=${encodeURIComponent(target)}`);
    assert.equal(res.status, 200);
    assert.match(res.body.body, /FLAG\{internal-only\}/);
  });

  test('SSRF: the safe unfurl blocks a loopback/private target', async () => {
    const target = `${await internal.url()}/internal/admin/flag`;
    const res = await lab.get(`/safe/a01/unfurl?url=${encodeURIComponent(target)}&as=alice`);
    assert.equal(res.status, 400);
    assert.match(res.body.error, /private|reserved|loopback/i);
  });

  test('SSRF: the safe unfurl blocks the cloud metadata address outright', async () => {
    const res = await lab.get(`/safe/a01/unfurl?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}&as=alice`);
    assert.equal(res.status, 400);
  });

  test('SSRF: the safe unfurl allows a genuine public host', async () => {
    const res = await lab.get(`/safe/a01/unfurl?url=${encodeURIComponent('http://example.com/')}&as=alice`);
    // Network may or may not be available in CI; either it fetched or it failed
    // at the socket, but it must NOT be blocked by the guard.
    assert.notEqual(res.status, 400);
  });
});
