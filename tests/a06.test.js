'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => lab.stop());

describe('A06:2025 Insecure Design', () => {
  test('coupon stacking: ten valid uses of one coupon make the order nearly free', async () => {
    const coupons = Array(10).fill('WELCOME10');
    const res = await lab.post('/vuln/a06/checkout', { json: { priceCents: 10000, coupons } });
    assert.ok(res.body.totalCents < 3500,
      `expected the price to collapse, got ${res.body.totalCents}`);
  });

  test('the designed-in rule rejects more than one coupon', async () => {
    const res = await lab.post('/safe/a06/checkout', { json: { priceCents: 10000, coupons: Array(10).fill('WELCOME10') } });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /one coupon/);
  });

  test('a single coupon still works — and only once', async () => {
    const first = await lab.post('/safe/a06/checkout', { json: { priceCents: 10000, coupons: ['WELCOME10'] } });
    assert.equal(first.body.totalCents, 9000);
    const second = await lab.post('/safe/a06/checkout', { json: { priceCents: 10000, coupons: ['WELCOME10'] } });
    assert.equal(second.status, 400);          // max_uses consumed
  });

  test('refund with no invariant: refund more than you ever paid', async () => {
    const res = await lab.post('/vuln/a06/refund', { json: { userId: 1, amountCents: 5_000_000 } });
    assert.ok(res.body.balance.balance_cents > 5_000_000);
  });

  test('the fixed refund is bounded by the invoice it refunds', async () => {
    const tooMuch = await lab.post('/safe/a06/refund', { json: { userId: 1, invoiceId: 1001, amountCents: 5_000_000 } });
    assert.equal(tooMuch.status, 400);

    const other = await lab.post('/safe/a06/refund', { json: { userId: 1, invoiceId: 1004, amountCents: 100 } });
    assert.equal(other.status, 404, "you cannot refund someone else's invoice");

    const ok = await lab.post('/safe/a06/refund', { json: { userId: 1, invoiceId: 1001, amountCents: 4200 } });
    assert.equal(ok.status, 200);
  });

  test('security questions are not a secret', async () => {
    const res = await lab.post('/vuln/a06/recover', { json: { username: 'carol', motherMaidenName: 'Smith' } });
    assert.equal(res.body.ok, true);
    assert.ok(res.body.resetToken, 'guessing a common surname handed over a reset token');
  });

  test('the fixed recovery never confirms an account or returns a token', async () => {
    const real = await lab.post('/safe/a06/recover', { json: { username: 'carol' } });
    const fake = await lab.post('/safe/a06/recover', { json: { username: 'not-a-user' } });
    assert.deepEqual(real.body, fake.body, 'the response must not distinguish real accounts');
    assert.equal(real.body.resetToken, undefined);
  });
});
