'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => { lab.stop(); });

describe('A04:2025 Cryptographic Failures', () => {
  test('reset token: Math.random() is short and guessable; randomBytes is long', async () => {
    const weak = await lab.get('/vuln/a04/reset-token');
    assert.ok(weak.body.token.length <= 8, `weak token was ${weak.body.token.length} chars`);
    const strong = await lab.get('/safe/a04/reset-token');
    assert.ok(strong.body.token.length >= 43, `strong token was ${strong.body.token.length} chars`);
  });

  test('password material: vuln leaks unsalted MD5; safe refuses (403)', async () => {
    const v = await lab.get('/vuln/a04/password-hashes');
    assert.equal(v.status, 200);
    const admin = v.body.rows.find((r) => r.username === 'admin');
    // Unsalted MD5 is trivially reversed: this is md5('admin').
    assert.equal(admin.password_md5, '21232f297a57a5a743894a0e4a801fc3');
    assert.equal((await lab.get('/safe/a04/password-hashes')).status, 403);
  });

  test('safe verify-password: right pw accepted, wrong rejected, nonexistent rejected', async () => {
    const ok = await lab.post('/safe/a04/verify-password', { json: { username: 'alice', password: 'password123' } });
    assert.equal(ok.body.ok, true);
    const wrong = await lab.post('/safe/a04/verify-password', { json: { username: 'alice', password: 'wrong-password' } });
    assert.equal(wrong.body.ok, false);
    const ghost = await lab.post('/safe/a04/verify-password', { json: { username: 'nobody', password: 'anything' } });
    assert.equal(ghost.body.ok, false);
  });

  test('AES-CBC bit-flip: rewrite "role":"user" to "role":"root" WITHOUT the key', async () => {
    // Two 16-byte blocks: filler in block 0, the target in block 1. "user" lands
    // at block-1 offsets 8..11, so we flip the SAME offsets in ciphertext block 0.
    const plaintext = 'AAAAAAAAAAAAAAAA' + '"role":"user","z';
    assert.equal(plaintext.length, 32);

    const sealed = await lab.post('/vuln/a04/seal', { json: { data: plaintext } });
    assert.equal(sealed.status, 200);
    const ct = Buffer.from(sealed.body.ciphertext, 'hex');

    // 'user' XOR 'root' — the delta we inject into the previous ciphertext block.
    const delta = [0x75 ^ 0x72, 0x73 ^ 0x6f, 0x65 ^ 0x6f, 0x72 ^ 0x74];
    for (let i = 0; i < 4; i += 1) ct[8 + i] ^= delta[i];

    const unsealed = await lab.post('/vuln/a04/unseal', { json: { ciphertext: ct.toString('hex') } });
    assert.equal(unsealed.status, 200);
    // Block 0 is now garbage, but block 1 decrypts to our forged role.
    const wantHex = Buffer.from('"role":"root"').toString('hex');
    assert.ok(unsealed.body.hex.includes(wantHex), 'forged "role":"root" not found in decrypted output');
  });

  test('AES-GCM: good ciphertext decrypts; a single flipped byte fails the tag', async () => {
    const sealed = await lab.post('/safe/a04/seal', { json: { data: '{"role":"user"}' } });
    assert.equal(sealed.status, 200);
    assert.ok(sealed.body.iv && sealed.body.tag);

    const good = await lab.post('/safe/a04/unseal', { json: sealed.body });
    assert.equal(good.status, 200);
    assert.match(good.body.plaintext, /"role":"user"/);

    // Flip one byte of ciphertext — GCM's auth tag must reject it.
    const tampered = { ...sealed.body };
    const buf = Buffer.from(tampered.ciphertext, 'hex');
    buf[0] ^= 0x01;
    tampered.ciphertext = buf.toString('hex');
    const bad = await lab.post('/safe/a04/unseal', { json: tampered });
    assert.equal(bad.status, 400);
    assert.match(bad.body.error, /integrity/i);
  });
});
