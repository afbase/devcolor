'use strict';
// Pre-flight check for the workshop. Run `npm run doctor` before you start.
const { execSync } = require('node:child_process');

let ok = true;
function check(label, fn) {
  try { const d = fn(); console.log(`  ✅ ${label}${d ? ' — ' + d : ''}`); }
  catch (err) { ok = false; console.log(`  ❌ ${label} — ${err.message}`); }
}

console.log('\nOWASP Top 10:2025 lab — environment check\n');
check('Node.js >= 18', () => { const m = Number(process.versions.node.split('.')[0]); if (m < 18) throw new Error(`found ${process.version}`); return process.version; });
check('better-sqlite3 loads', () => { require('better-sqlite3'); return 'ok (run `npm rebuild better-sqlite3` if this fails)'; });
check('express installed', () => require('express/package.json').version);
check('prom-client installed', () => require('prom-client/package.json').version);
check('database migrates + seeds', () => {
  process.env.LAB_DB = ':memory:';
  const { db } = require('../app/db');
  const users = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const mig = db.prepare('SELECT COUNT(*) c FROM _migrations').get().c;
  if (users < 5 || mig < 2) throw new Error('seed/migrate looks wrong');
  return `${users} users, ${mig} migrations`;
});
check('curl available (used in exercises)', () => { execSync('curl --version', { stdio: 'pipe' }); return 'ok'; });
check('docker available (optional — for the full stack)', () => { execSync('docker --version', { stdio: 'pipe' }); return 'ok'; });

console.log(ok
  ? '\nAll good.\n  Local:  npm start        → http://localhost:3000\n  Full:   docker compose up → portal :3000, Grafana :3001, Prometheus :9090\n'
  : '\nSomething needs attention before the workshop.\n');
process.exit(ok ? 0 : 1);
