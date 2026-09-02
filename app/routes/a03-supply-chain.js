'use strict';
/**
 * A03:2025 — Software Supply Chain Failures  (NEW, and #1 in the community survey)
 *
 * 2021 had "Vulnerable and Outdated Components." 2025 widens it to the whole
 * supply chain: not just "is a dependency old" but "what did I actually install,
 * what ran code on my build machine, and can I reproduce this build tomorrow?"
 *
 * The uncomfortable arithmetic every Node project lives with: you write down a
 * handful of dependencies, and `npm install` fetches a hundred. Any one of them
 * can run arbitrary code at install time. This lab doesn't exploit anything — it
 * makes the invisible visible. Point `/inventory` at your own tree and look.
 *
 * VULN and SAFE serve the SAME `/inventory` — the facts don't change. What
 * changes is the discipline around them: `/resolution` contrasts the two.
 */
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.join(__dirname, '..', '..');
const PKG_PATH = path.join(REPO_ROOT, 'package.json');
const LOCK_PATH = path.join(REPO_ROOT, 'package-lock.json');
const NODE_MODULES = path.join(REPO_ROOT, 'node_modules');

// Walk node_modules and count what is ACTUALLY on disk (scoped packages count
// individually), and note which ones declare install-time lifecycle scripts —
// preinstall/install/postinstall run code the moment you `npm install`.
function scanNodeModules() {
  let installed = 0;
  const runsCodeAtInstall = [];
  const record = (name, dir) => {
    installed += 1;
    try {
      const p = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
      const s = p.scripts || {};
      if (s.preinstall || s.install || s.postinstall) runsCodeAtInstall.push(name);
    } catch { /* no/broken package.json — ignore, still counts as installed */ }
  };
  if (!fs.existsSync(NODE_MODULES)) return { installed, runsCodeAtInstall };
  for (const name of fs.readdirSync(NODE_MODULES)) {
    if (name.startsWith('.') || name === '.bin') continue;
    if (name.startsWith('@')) {
      for (const sub of fs.readdirSync(path.join(NODE_MODULES, name))) {
        if (sub.startsWith('.')) continue;
        record(`${name}/${sub}`, path.join(NODE_MODULES, name, sub));
      }
    } else {
      record(name, path.join(NODE_MODULES, name));
    }
  }
  return { installed, runsCodeAtInstall };
}

function buildInventory() {
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
  const direct = Object.keys(pkg.dependencies || {});
  const { installed, runsCodeAtInstall } = scanNodeModules();
  return {
    directDependencies: direct.length,           // what you wrote down
    directDependencyNames: direct,
    packagesActuallyInstalled: installed,         // what npm actually fetched
    transitiveMultiplier: direct.length ? Math.round((installed / direct.length) * 10) / 10 : 0,
    packagesThatRunCodeAtInstallTime: runsCodeAtInstall.length,
    packagesThatRunCodeAtInstallTimeNames: runsCodeAtInstall,
    lockfilePresent: fs.existsSync(LOCK_PATH),
    lesson: 'You audited ' + direct.length + ' names. Your trust boundary is ' +
      installed + ' packages, ' + runsCodeAtInstall.length + ' of which run code on your build machine.',
  };
}

// The inventory is a fact of the tree, not of the route. Both sides serve it.
function mountInventory(router) {
  router.get('/inventory', (req, res) => res.json(buildInventory()));
}

// =============================================================================
// VULNERABLE — "just npm install and ship it"
// =============================================================================
const vuln = express.Router();
mountInventory(vuln);

// The vulnerable posture: caret ranges + `npm install` on every build + no
// lockfile discipline. `express: "^4.21.1"` means "4.21.1 or any newer 4.x we
// happen to resolve." A compromised patch release of a transitive dep lands in
// your build silently, and two builds of the same commit differ.
vuln.get('/resolution', (req, res) => {
  res.json({
    posture: 'insecure',
    installCommand: 'npm install',
    respectsLockfile: false,
    example: { declared: 'express: "^4.21.1"', mayResolveTo: '4.21.1 … 4.99.99, whatever is newest at build time' },
    why: 'A caret range plus `npm install` lets a freshly published (or freshly compromised) version enter your build with no code review and no reproducibility.',
  });
});

// =============================================================================
// SECURE — pin, lock, and install from the lockfile
// =============================================================================
const safe = express.Router();
mountInventory(safe);

// The secure posture: a committed lockfile + `npm ci`, which installs the EXACT
// versions in package-lock.json (with integrity hashes) and errors if the lock
// and manifest disagree. `--ignore-scripts` in CI stops install-time code from
// running at all. Reproducible builds are a security property.
safe.get('/resolution', (req, res) => {
  const lock = fs.existsSync(LOCK_PATH) ? JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8')) : null;
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
  // Show that every direct dependency is pinned to an exact version + integrity hash.
  const pinned = {};
  for (const name of Object.keys(pkg.dependencies || {})) {
    const entry = lock && lock.packages ? lock.packages[`node_modules/${name}`] : null;
    pinned[name] = entry
      ? { version: entry.version, resolved: Boolean(entry.resolved), integrity: Boolean(entry.integrity) }
      : { version: null, resolved: false, integrity: false };
  }
  res.json({
    posture: 'secure',
    installCommand: 'npm ci --ignore-scripts',
    respectsLockfile: true,
    lockfilePresent: Boolean(lock),
    directDependenciesPinned: pinned,
    why: '`npm ci` installs the exact locked versions and verifies each integrity hash; a mismatch fails the build. `--ignore-scripts` prevents install-time code execution.',
  });
});

module.exports = { vuln, safe };
