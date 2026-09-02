'use strict';
/**
 * A08:2025 — Software or Data Integrity Failures  (#8)
 *
 * "Software and data integrity failures relate to code and infrastructure that
 *  does not protect against integrity violations." In plain terms: you trusted
 *  data (or an update) that you never verified came from where it claimed.
 *
 * Two classic shapes live here:
 *   1. Untrusted deserialization / merge → PROTOTYPE POLLUTION. A recursive
 *      merge of attacker JSON into your objects lets `__proto__` reach up and
 *      rewrite Object.prototype, so *every* object in the process silently
 *      grows attacker-chosen properties (e.g. isAdmin:true).
 *   2. An auto-update / plugin channel that applies a payload WITHOUT verifying
 *      a signature. Anyone who can reach the endpoint ships you code/config.
 */
const express = require('express');
const crypto = require('node:crypto');

// A real system would load this from a KMS / secret manager and the signer
// would be a separate service. We export it so the TEST can play the role of
// the legitimate signer — that's the whole point of a shared secret.
const UPDATE_SECRET = 'workshop-shared-hmac-secret-do-not-ship';

// The server's own defaults. In the vuln handler we merge user input on top of
// a COPY of this — which is exactly where the trouble starts.
const PREFERENCE_DEFAULTS = { theme: 'light', pageSize: 20 };

// =============================================================================
// VULNERABLE
// =============================================================================
const vuln = express.Router();
vuln.use(express.json());

/**
 * The textbook unsafe deep-merge. It walks every key of the source and, when a
 * value is an object, recurses. The fatal move is using bracket access on the
 * TARGET: when the incoming key is "__proto__", `target[key]` is not a normal
 * property — it's the object's prototype. So we recurse straight into
 * Object.prototype and start writing attacker keys onto it.
 */
function unsafeMerge(target, source) {
  for (const key in source) {
    const value = source[key];
    if (value && typeof value === 'object') {
      // No key filtering. `target[key]` for key==="__proto__" IS Object.prototype.
      if (typeof target[key] !== 'object' || target[key] === null) target[key] = {};
      unsafeMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

vuln.post('/preferences', (req, res) => {
  // Snapshot Object.prototype's own keys BEFORE so we can prove (and then
  // clean up) the damage the merge does. In a real exploit nobody cleans up —
  // that's why one poisoned request corrupts the whole process.
  const cleanKeys = new Set(Object.getOwnPropertyNames(Object.prototype));

  // Merge attacker JSON onto a fresh copy of the defaults. Looks harmless.
  const merged = unsafeMerge({ ...PREFERENCE_DEFAULTS }, req.body || {});

  // The smoking gun: a brand-new object that NEVER touched the request now
  // inherits the attacker's properties, because they live on Object.prototype.
  const bystander = {};
  const evidence = { isAdmin: bystander.isAdmin, role: bystander.role };

  // SCRUB — undo the pollution so the rest of the test suite (and this process)
  // isn't corrupted. Everything added to Object.prototype since the snapshot
  // gets deleted. This is teaching hygiene, NOT part of the vulnerability.
  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    if (!cleanKeys.has(key)) delete Object.prototype[key];
  }

  res.json({ merged, pollutedBystanderObject: evidence });
});

/**
 * The unsigned update channel. Hand it any {name, payload} and it "applies" it.
 * There is no proof the payload came from your build pipeline — so this is a
 * remote-code/remote-config injection waiting to happen (think: a poisoned
 * auto-update, a malicious CI artifact, a tampered plugin).
 */
vuln.post('/apply-update', (req, res) => {
  const { name, payload } = req.body || {};
  if (!name || payload === undefined) return res.status(400).json({ error: 'need {name, payload}' });
  // Applied blindly. No signature, no checksum, no provenance.
  res.json({ applied: true, name, payload });
});

// =============================================================================
// SECURE
// =============================================================================
const safe = express.Router();
safe.use(express.json());

// The only keys we accept. An allow-list is the honest fix: unknown keys —
// including the dangerous "__proto__"/"constructor"/"prototype" — never make it
// into our object at all.
const ALLOWED_PREFS = new Set(['theme', 'pageSize']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

safe.post('/preferences', (req, res) => {
  const input = req.body || {};

  // Reject outright if the caller even tries the polluting keys — clearer than
  // silently dropping them, and it shows up in logs.
  for (const key of Object.keys(input)) {
    if (FORBIDDEN_KEYS.has(key)) {
      return res.status(400).json({ error: `refused dangerous key: ${key}` });
    }
  }

  // Build on a null-prototype object so there is NO prototype to pollute, then
  // copy across only keys we recognise. Two independent defences on purpose.
  const prefs = Object.assign(Object.create(null), PREFERENCE_DEFAULTS);
  for (const key of Object.keys(input)) {
    if (ALLOWED_PREFS.has(key)) prefs[key] = input[key];
  }

  // Prove the prototype is still clean for the bystander object.
  const bystander = {};
  res.json({
    merged: { theme: prefs.theme, pageSize: prefs.pageSize },
    prototypeClean: bystander.isAdmin === undefined && bystander.role === undefined,
  });
});

/**
 * Sign the payload the way the pipeline would, so the test (the legitimate
 * signer) can reproduce it. HMAC-SHA256 over the canonical JSON of the payload.
 */
function signPayload(payload) {
  return crypto.createHmac('sha256', UPDATE_SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
}

safe.post('/apply-update', (req, res) => {
  const { name, payload, signature } = req.body || {};
  if (!name || payload === undefined) return res.status(400).json({ error: 'need {name, payload, signature}' });
  if (!signature) return res.status(400).json({ error: 'unsigned update rejected' });

  const expected = signPayload(payload);
  const got = Buffer.from(String(signature), 'utf8');
  const want = Buffer.from(expected, 'utf8');

  // Constant-time compare: timingSafeEqual needs equal-length buffers, so the
  // length check up front doubles as a guard against a comparison throw. A
  // real library (e.g. an SRI/Sigstore verifier) does this for you.
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
    return res.status(400).json({ error: 'signature verification failed' });
  }

  res.json({ applied: true, name, payload, verified: true });
});

module.exports = { vuln, safe, UPDATE_SECRET, signPayload };
