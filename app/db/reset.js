'use strict';
const fs = require('node:fs');
const path = require('node:path');

// `npm run db:reset` — delete the file-backed database so the next boot
// re-migrates and re-seeds from scratch. No-op for in-memory.
const file = process.env.LAB_DB || path.join(__dirname, '..', '..', 'data', 'lab.db');
for (const f of [file, `${file}-wal`, `${file}-shm`]) {
  if (fs.existsSync(f)) { fs.rmSync(f); console.log(`  removed ${f}`); }
}
console.log('  database reset — next start will migrate + seed.');
