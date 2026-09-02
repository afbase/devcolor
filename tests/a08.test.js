'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startLab } = require('./helpers');
const { UPDATE_SECRET } = require('../app/routes/a08-integrity-failures');

const lab = startLab();
after(() => { lab.stop(); });

describe('A08:2025 Software or Data Integrity Failures', () => {
  test('prototype pollution: __proto__ merge poisons an unrelated bystander object', async () => {
    // Build via JSON.parse: an object LITERAL `{ __proto__: ... }` sets the
    // prototype, so it would serialise to `{}`. JSON.parse makes "__proto__" a
    // real own key — exactly the bytes an attacker puts on the wire.
    const poison = JSON.parse('{"__proto__":{"isAdmin":true,"role":"admin"}}');
    const res = await lab.post('/vuln/a08/preferences', { json: poison });
    assert.equal(res.status, 200);
    // A brand-new object that never touched the request inherited the props.
    assert.equal(res.body.pollutedBystanderObject.isAdmin, true);
    assert.equal(res.body.pollutedBystanderObject.role, 'admin');
    // And the handler scrubbed Object.prototype so THIS process isn't corrupt.
    assert.equal(({}).isAdmin, undefined);
  });

  test('safe preferences: dangerous keys rejected, prototype stays clean', async () => {
    const res = await lab.post('/safe/a08/preferences', {
      json: JSON.parse('{"__proto__":{"isAdmin":true}}'),
    });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /__proto__/);
    assert.equal(({}).isAdmin, undefined);
  });

  test('safe preferences: still applies a legitimate allow-listed key', async () => {
    const res = await lab.post('/safe/a08/preferences', { json: { theme: 'dark', bogus: 'x' } });
    assert.equal(res.status, 200);
    assert.equal(res.body.merged.theme, 'dark');
    assert.equal(res.body.prototypeClean, true);
    // Unknown key was dropped, not merged.
    assert.equal(res.body.merged.bogus, undefined);
  });

  test('vuln apply-update: applies any payload with no signature', async () => {
    const res = await lab.post('/vuln/a08/apply-update', {
      json: { name: 'evil-plugin', payload: { code: 'rm -rf /' } },
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.applied, true);
  });

  test('safe apply-update: rejects unsigned and tampered, accepts a valid signature', async () => {
    const payload = { version: '2.0.0', url: 'https://cdn.example/app-2.0.0.tgz' };
    const signature = crypto.createHmac('sha256', UPDATE_SECRET)
      .update(JSON.stringify(payload)).digest('hex');

    // Unsigned → rejected.
    const unsigned = await lab.post('/safe/a08/apply-update', { json: { name: 'app', payload } });
    assert.equal(unsigned.status, 400);

    // Tampered payload under a valid-for-the-old-payload signature → rejected.
    const tampered = await lab.post('/safe/a08/apply-update', {
      json: { name: 'app', payload: { ...payload, url: 'https://evil.example/backdoor.tgz' }, signature },
    });
    assert.equal(tampered.status, 400);
    assert.match(tampered.body.error, /verification failed/);

    // Correctly signed → applied.
    const good = await lab.post('/safe/a08/apply-update', { json: { name: 'app', payload, signature } });
    assert.equal(good.status, 200);
    assert.equal(good.body.verified, true);
  });
});
