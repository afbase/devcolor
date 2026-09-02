'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');

const lab = startLab();
after(() => { lab.stop(); });

describe('A09:2025 Security Logging & Alerting Failures', () => {
  test('vuln login: 50 failed logins leave the log completely empty', async () => {
    for (let i = 0; i < 50; i++) {
      await lab.post('/vuln/a09/login', { json: { username: 'alice', password: `wrong-${i}` } });
    }
    const logs = await lab.get('/vuln/a09/logs');
    assert.equal(logs.status, 200);
    assert.equal(logs.text.trim(), ''); // an attack that is completely invisible
  });

  test('log injection: a newline forges a line on vuln, but is one escaped record on safe', async () => {
    const evil = 'eve\n2099-01-01T00:00:00.000Z INFO login attempt user=admin GRANTED';

    await lab.post('/vuln/a09/audit', { json: { username: evil } });
    const vlogs = await lab.get('/vuln/a09/logs');
    // The embedded newline split into TWO lines — a forged admin entry.
    const forged = vlogs.text.split('\n').filter((l) => /user=admin GRANTED/.test(l));
    assert.equal(forged.length, 1);
    assert.ok(vlogs.text.split('\n').length >= 2);

    await lab.post('/safe/a09/audit', { json: { username: evil } });
    const slogs = await lab.get('/safe/a09/logs');
    const lines = slogs.text.split('\n').filter(Boolean);
    // Exactly one record, and it parses — the newline lives inside the field.
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]);
    assert.equal(rec.event, 'audit.login_attempt');
    assert.equal(rec.username, evil); // preserved verbatim, not executed
  });

  test('secrets: a card number is logged raw on vuln, [REDACTED] on safe', async () => {
    await lab.post('/vuln/a09/checkout', { json: { item: 'book', cardNumber: '4111111111111111' } });
    const vlogs = await lab.get('/vuln/a09/logs');
    assert.match(vlogs.text, /4111111111111111/);

    await lab.post('/safe/a09/checkout', { json: { item: 'book', cardNumber: '4111111111111111' } });
    const slogs = await lab.get('/safe/a09/logs');
    assert.doesNotMatch(slogs.text, /4111111111111111/);
    assert.match(slogs.text, /\[REDACTED\]/);
  });

  test('safe login: failures are structured, parseable JSON with event auth.failed', async () => {
    const res = await lab.post('/safe/a09/login', { json: { username: 'mallory', password: 'nope' } });
    assert.equal(res.status, 401);
    const slogs = await lab.get('/safe/a09/logs');
    const records = slogs.text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const failed = records.filter((r) => r.event === 'auth.failed');
    assert.ok(failed.length >= 1);
    // The password made it into a redacted field, not the clear.
    assert.equal(failed[0].password, '[REDACTED]');
  });

  test('alerting: 6 failed logins for one user trip a brute_force alert', async () => {
    for (let i = 0; i < 6; i++) {
      await lab.post('/safe/a09/login', { json: { username: 'victim', password: `guess-${i}` } });
    }
    const res = await lab.get('/safe/a09/alerts');
    assert.equal(res.status, 200);
    const brute = res.body.alerts.filter(
      (a) => a.event === 'ALERT.brute_force_suspected' && a.username === 'victim',
    );
    assert.ok(brute.length >= 1);
  });

  test('metrics: the safe side feeds the counters Grafana graphs; the vuln side does not', async () => {
    const metrics = await lab.get('/metrics');
    assert.match(metrics.text, /lab_auth_attempts_total\{[^}]*result="failure"[^}]*\}/);
    assert.match(metrics.text, /lab_security_alerts_total\{[^}]*kind="brute_force"[^}]*\}/);
  });
});
