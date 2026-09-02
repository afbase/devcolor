'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => { lab.stop(); });

// alice is userId 1, bob is userId 2, admin is userId 4 (see app/db/seed.js).
const ALICE = 1;
const BOB = 2;
const ADMIN = 4;

describe('A10:2025 Mishandling of Exceptional Conditions', () => {
  test('fail open vs fail closed: authz down → vuln allows, safe returns 503', async () => {
    await lab.post('/vuln/a10/authz-service/down'); // shared toggle

    const v = await lab.post('/vuln/a10/admin-action', { json: { userId: BOB } });
    assert.equal(v.status, 200);
    assert.equal(v.body.allowed, true); // fails OPEN — everyone is admin

    const s = await lab.post('/safe/a10/admin-action', { json: { userId: BOB } });
    assert.equal(s.status, 503); // fails CLOSED

    await lab.post('/vuln/a10/authz-service/up'); // restore for the next test
  });

  test('safe admin-action: allows the real admin, denies everyone else', async () => {
    assert.equal((await lab.post('/safe/a10/admin-action', { json: { userId: ADMIN } })).status, 200);
    assert.equal((await lab.post('/safe/a10/admin-action', { json: { userId: ALICE } })).status, 403);
  });

  test('error handling: vuln /report leaks the stack, safe returns a reference with no stack', async () => {
    const v = await lab.get('/vuln/a10/report?table=does_not_exist');
    assert.equal(v.status, 500);
    assert.ok(v.body.stack, 'vuln leaks a stack trace');
    assert.match(v.body.error, /no such table/);

    const s = await lab.get('/safe/a10/report?table=does_not_exist');
    assert.equal(s.status, 400); // unknown table → clean rejection
    assert.equal(s.body.stack, undefined);
    assert.ok(s.body.reference, 'safe returns an opaque reference');

    // An allow-listed table still works on the safe side.
    const ok = await lab.get('/safe/a10/report?table=accounts');
    assert.equal(ok.status, 200);
    assert.ok(Array.isArray(ok.body.rows));
  });

  test('no atomicity: vuln transfer with failMidway loses money; safe rolls back', async () => {
    const amount = 10000;

    // --- VULN: money vanishes ---
    const before = (await lab.get('/vuln/a10/balances')).body;
    const aliceBefore = before.accounts.find((a) => a.user_id === ALICE).balance_cents;
    const bobBefore = before.accounts.find((a) => a.user_id === BOB).balance_cents;

    const failed = await lab.post('/vuln/a10/transfer?failMidway=1', {
      json: { fromUserId: ALICE, toUserId: BOB, amountCents: amount },
    });
    assert.equal(failed.status, 500);

    const after1 = (await lab.get('/vuln/a10/balances')).body;
    const aliceAfter = after1.accounts.find((a) => a.user_id === ALICE).balance_cents;
    const bobAfter = after1.accounts.find((a) => a.user_id === BOB).balance_cents;
    assert.equal(aliceAfter, aliceBefore - amount);  // alice was debited
    assert.equal(bobAfter, bobBefore);               // bob never credited
    assert.equal(after1.total, before.total - amount); // the money is GONE

    // --- SAFE: rollback conserves the total ---
    const sBefore = (await lab.get('/safe/a10/balances')).body;
    const rolled = await lab.post('/safe/a10/transfer?failMidway=1', {
      json: { fromUserId: ALICE, toUserId: BOB, amountCents: amount },
    });
    assert.equal(rolled.status, 409);
    const sAfter = (await lab.get('/safe/a10/balances')).body;
    assert.deepEqual(sAfter.accounts, sBefore.accounts); // nothing moved
    assert.equal(sAfter.total, sBefore.total);           // total conserved

    // --- SAFE happy path: money moves exactly once ---
    const hBefore = (await lab.get('/safe/a10/balances')).body;
    const aB = hBefore.accounts.find((a) => a.user_id === ALICE).balance_cents;
    const bB = hBefore.accounts.find((a) => a.user_id === BOB).balance_cents;
    const okTransfer = await lab.post('/safe/a10/transfer', {
      json: { fromUserId: ALICE, toUserId: BOB, amountCents: amount },
    });
    assert.equal(okTransfer.status, 200);
    const hAfter = (await lab.get('/safe/a10/balances')).body;
    assert.equal(hAfter.accounts.find((a) => a.user_id === ALICE).balance_cents, aB - amount);
    assert.equal(hAfter.accounts.find((a) => a.user_id === BOB).balance_cents, bB + amount);
    assert.equal(hAfter.total, hBefore.total); // conserved
  });
});
