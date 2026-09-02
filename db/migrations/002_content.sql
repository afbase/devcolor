-- 002_content.sql — user-generated content and integration surfaces.
-- These tables back the stored-XSS (A05), SSRF (A01) and integrity (A08) labs.

-- Public guestbook / activity wall: anyone can post, everyone sees it.
-- This is the stored-XSS surface — a payload saved once runs for every viewer.
CREATE TABLE guestbook (
  id         INTEGER PRIMARY KEY,
  author     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Support tickets: a customer writes free text, an agent reads it in an admin
-- console. Second stored-XSS surface, and it crosses a privilege boundary.
CREATE TABLE support_tickets (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  subject    TEXT NOT NULL,
  body       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Outbound webhooks / link-unfurl targets: the app fetches a user-supplied URL.
-- This is the SSRF surface (A01, CWE-918).
CREATE TABLE webhooks (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  label      TEXT NOT NULL,
  target_url TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Signed artifacts for the integrity lab (A08): a name, a payload, a signature.
CREATE TABLE artifacts (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  applied    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
