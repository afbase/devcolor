'use strict';
const path = require('node:path');
const fs = require('node:fs');
const Database = require('better-sqlite3');
const { migrate } = require('./migrate');
const { seed, md5, scryptHash, scryptVerify } = require('./seed');

/**
 * Open a database, run pending migrations, and populate seed data.
 *
 *   - The running app (Docker) sets LAB_DB=/data/lab.db, so state persists.
 *   - Tests import the singleton below in their own process; with no LAB_DB
 *     it is an in-memory database, freshly migrated and seeded per test file.
 */
function openDatabase(file = process.env.LAB_DB || ':memory:') {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  migrate(db);
  seed(db);
  return db;
}

// Singleton used throughout the app. Routes do: const { db } = require('../db')
const db = openDatabase();

module.exports = { db, openDatabase, md5, scryptHash, scryptVerify };
