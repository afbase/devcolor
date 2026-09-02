'use strict';
const crypto = require('node:crypto');

// Two session stores so labs can compare them directly (A07).

// VULNERABLE: sequential, guessable IDs; no rotation on login (fixation).
let counter = 1000;
const weakSessions = new Map();
function weakCreate(userId = null) { const id = `sess-${++counter}`; weakSessions.set(id, { userId }); return id; }
function weakGet(id) { return weakSessions.get(id) || null; }
function weakLogin(id, userId) { const s = weakSessions.get(id) || {}; s.userId = userId; weakSessions.set(id, s); return id; }

// SAFE: 256 bits of CSPRNG entropy, fresh ID at every privilege change.
const strongSessions = new Map();
function strongCreate(userId = null) { const id = crypto.randomBytes(32).toString('base64url'); strongSessions.set(id, { userId, createdAt: Date.now() }); return id; }
function strongGet(id) { return strongSessions.get(id) || null; }
function strongLogin(oldId, userId) { strongSessions.delete(oldId); return strongCreate(userId); }
function strongDestroy(id) { strongSessions.delete(id); }

module.exports = {
  weak:   { create: weakCreate,   get: weakGet,   login: weakLogin,   store: weakSessions },
  strong: { create: strongCreate, get: strongGet, login: strongLogin, destroy: strongDestroy, store: strongSessions },
};
