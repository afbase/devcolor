-- 001_core.sql — accounts, money, and the audit trail.
-- Applied in filename order by app/db/migrate.js and tracked in _migrations.

CREATE TABLE users (
  id              INTEGER PRIMARY KEY,
  username        TEXT NOT NULL UNIQUE,
  email           TEXT NOT NULL,
  full_name       TEXT NOT NULL DEFAULT '',
  role            TEXT NOT NULL DEFAULT 'user',
  -- A04: two columns on purpose so labs can compare a bad hash to a good one.
  password_md5    TEXT NOT NULL,
  password_scrypt TEXT NOT NULL,
  mfa_enabled     INTEGER NOT NULL DEFAULT 0,
  failed_logins   INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE accounts (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  balance_cents INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE invoices (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  amount_cents INTEGER NOT NULL,
  memo         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE coupons (
  code        TEXT PRIMARY KEY,
  percent_off INTEGER NOT NULL,
  times_used  INTEGER NOT NULL DEFAULT 0,
  max_uses    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE audit_log (
  id     INTEGER PRIMARY KEY,
  at     TEXT NOT NULL,
  actor  TEXT,
  event  TEXT NOT NULL,
  detail TEXT
);
