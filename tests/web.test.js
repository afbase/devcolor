'use strict';
// Integration smoke for the LinkedIn-style front end: the feed renders one post
// per lab, every profile page renders, and every bench action maps to a real
// mounted endpoint (never the "route failed to load" placeholder, never 404).
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const { startLab } = require('./helpers');
const { ORDER } = require('../app/web/labs');

const lab = startLab();
after(() => lab.stop());
const CODES = ORDER.map(([c]) => c);

function readLabData(html) {
  const m = html.match(/id="lab-data">([\s\S]*?)<\/script>/);
  assert.ok(m, 'lab-data JSON block present');
  return JSON.parse(m[1].replace(/\\u003c/g, '<'));
}
function fill(str, inputs) {
  return String(str).replace(/\{(\w+)\}/g, (_, k) => {
    const i = (inputs || []).find((x) => x.name === k);
    return i ? encodeURIComponent(i.default != null ? i.default : '') : '';
  });
}

describe('Front-end feed + profiles', () => {
  test('the feed renders one post per lab', async () => {
    const res = await lab.get('/');
    assert.equal(res.status, 200);
    assert.equal((res.text.match(/class="card post"/g) || []).length, CODES.length);
    assert.match(res.text, /class="brand"/);
  });

  for (const code of CODES) {
    test(`/lab/${code} renders a real profile with a populated bench`, async () => {
      const res = await lab.get(`/lab/${code}`);
      assert.equal(res.status, 200);
      const data = readLabData(res.text);
      assert.equal(data.code, code);
      assert.ok(data.bench.actions.length > 0, `${code} must have bench actions`);
      assert.match(res.text, /src="\/static\/bench.js"/);
    });
  }

  test('every bench action resolves on a real endpoint (never the unmounted placeholder)', async () => {
    for (const code of CODES) {
      const data = readLabData((await lab.get(`/lab/${code}`)).text);
      for (const a of data.bench.actions) {
        const path = fill(a.path || '/', a.inputs);
        const qs = [];
        if (a.query) for (const [k, v] of Object.entries(a.query)) qs.push(`${k}=${fill(v, a.inputs)}`);
        const suffix = `${path}${qs.length ? '?' + qs.join('&') : ''}`;
        const method = (a.method || 'GET').toLowerCase();
        const opts = method === 'post'
          ? { json: a.body ? JSON.parse(fill(JSON.stringify(a.body), a.inputs)) : {} }
          : undefined;
        const sides = a.sides || ['vuln', 'safe'];
        let anyResolved = false;
        for (const side of sides) {
          const res = await lab[method === 'post' ? 'post' : 'get'](`/${side}/${code}${suffix}`, opts);
          // A module that failed to load answers 500 with this body on every path.
          if (res.status === 500 && res.body && /failed to load/.test(res.body.error || '')) {
            assert.fail(`${code} route not mounted for /${side}/${code}${suffix}`);
          }
          if (res.status !== 404) anyResolved = true;
        }
        // A typo'd path would 404 on ALL sides; an intentional single-side
        // action (e.g. A09 /alerts only exists on /safe) still resolves once.
        assert.ok(anyResolved, `${code} action "${a.id || a.title}" 404s on every side (${suffix})`);
      }
    }
  });
});
