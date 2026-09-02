'use strict';
const { test, after, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startLab } = require('./helpers');

const REPO_ROOT = path.join(__dirname, '..');
const lab = startLab();
after(() => { lab.stop(); });

describe('A03:2025 Software Supply Chain Failures', () => {
  test('/inventory counts 3 declared deps but many more actually installed', async () => {
    const res = await lab.get('/vuln/a03/inventory');
    assert.equal(res.status, 200);
    assert.equal(res.body.directDependencies, 3);
    assert.ok(res.body.packagesActuallyInstalled > 20,
      `expected >20 installed, got ${res.body.packagesActuallyInstalled}`);
    // The whole lesson in one number: your trust boundary is far bigger than 3.
    assert.ok(res.body.transitiveMultiplier > 1);
    assert.ok(res.body.packagesThatRunCodeAtInstallTime >= 1);
  });

  test('both sides serve the same inventory (facts, not framing)', async () => {
    const v = await lab.get('/vuln/a03/inventory');
    const s = await lab.get('/safe/a03/inventory');
    assert.equal(v.body.directDependencies, s.body.directDependencies);
    assert.equal(v.body.packagesActuallyInstalled, s.body.packagesActuallyInstalled);
  });

  test('a committed lockfile exists at the repo root', () => {
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'package-lock.json')));
  });

  test('every direct dependency is pinned in the lockfile with a version + integrity/resolved', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package-lock.json'), 'utf8'));
    const direct = Object.keys(pkg.dependencies || {});
    assert.deepEqual(direct.sort(), ['better-sqlite3', 'express', 'prom-client']);
    for (const name of direct) {
      const entry = lock.packages[`node_modules/${name}`];
      assert.ok(entry, `${name} missing from lockfile`);
      assert.match(entry.version, /^\d+\.\d+\.\d+/, `${name} not pinned to an exact version`);
      assert.ok(entry.resolved, `${name} has no resolved URL`);
      assert.ok(entry.integrity, `${name} has no integrity hash`);
    }
  });

  test('/resolution on safe reports every direct dep as pinned', async () => {
    const res = await lab.get('/safe/a03/resolution');
    assert.equal(res.status, 200);
    assert.equal(res.body.respectsLockfile, true);
    for (const name of ['better-sqlite3', 'express', 'prom-client']) {
      assert.ok(res.body.directDependenciesPinned[name].version, `${name} not reported pinned`);
      assert.equal(res.body.directDependenciesPinned[name].integrity, true);
    }
  });

  test('CI installs from the lockfile: uses `npm ci` and never `npm install`', () => {
    const ci = fs.readFileSync(path.join(REPO_ROOT, '.github/workflows/ci.yml'), 'utf8');
    assert.match(ci, /npm ci/);
    assert.doesNotMatch(ci, /run:\s*npm install/);
  });
});
