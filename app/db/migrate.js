'use strict';
const fs = require('node:fs');
const path = require('node:path');

const MIGRATIONS_DIR = path.join(__dirname, '..', '..', 'db', 'migrations');

/**
 * Apply every db/migrations/*.sql file that hasn't run yet, in filename order.
 * Applied migrations are recorded in _migrations so this is safe to run on
 * every boot (idempotent) — the file-backed Docker database keeps its history,
 * and a fresh in-memory test database simply re-applies everything.
 */
function migrate(db, { log = false } = {}) {
  db.exec(`CREATE TABLE IF NOT EXISTS _migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const applied = new Set(db.prepare('SELECT name FROM _migrations').all().map((r) => r.name));
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort();

  let ran = 0;
  const apply = db.transaction((file) => {
    db.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8'));
    db.prepare('INSERT INTO _migrations (name) VALUES (?)').run(file);
  });

  for (const file of files) {
    if (applied.has(file)) continue;
    apply(file);
    ran += 1;
    if (log) console.log(`  migrated ${file}`);
  }
  return { ran, total: files.length };
}

module.exports = { migrate, MIGRATIONS_DIR };

// `npm run db:migrate` — apply migrations to the configured database file.
if (require.main === module) {
  const Database = require('better-sqlite3');
  const file = process.env.LAB_DB || path.join(__dirname, '..', '..', 'data', 'lab.db');
  const db = new Database(file);
  const { ran, total } = migrate(db, { log: true });
  console.log(`\n  ${file}\n  ${ran} migration(s) applied, ${total} total.`);
}
