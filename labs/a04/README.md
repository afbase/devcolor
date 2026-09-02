# A04:2025 — Cryptographic Failures

> ▼ #2 → #4. It slipped a couple of places, but the failures didn't get more
> exotic — they got more basic. The 2025 data is dominated by *weak randomness*
> and by cipher modes that keep data secret but don't stop it being *rewritten*.

**The one-sentence version:** use a real CSPRNG, never hand out password
material, store passwords with a slow salted KDF, and encrypt with an
*authenticated* mode so tampering is detected — not just decrypted.

Source files: [`app/routes/a04-cryptographic-failures.js`](../../app/routes/a04-cryptographic-failures.js)
· Tests: [`tests/a04.test.js`](../../tests/a04.test.js)

---

## Break it

Start the app (`npm start`) and, in another terminal:

```bash
# 1) Predictable tokens — Math.random() gives ~8 chars of guessable base36.
curl -s "http://localhost:3000/vuln/a04/reset-token"
curl -s "http://localhost:3000/safe/a04/reset-token"   # 43 chars of CSPRNG entropy

# 2) The endpoint hands out password hashes — unsalted MD5, cracked instantly.
curl -s "http://localhost:3000/vuln/a04/password-hashes"
curl -s "http://localhost:3000/safe/a04/password-hashes"   # 403, always

# 3) AES-CBC with a static IV and no auth tag: rewrite the plaintext w/o the key.
#    (walk it by hand below — the test automates the same attack)
```

### The CBC bit-flip, by hand

CBC decrypts block *i* as `P_i = D(C_i) XOR C_{i-1}`. Change a byte of ciphertext
block *i−1* and you change the *same* byte of plaintext block *i*, predictably —
no key required. There's no auth tag to catch it.

```bash
# Seal a payload whose "role":"user" sits in block 2 (bytes 16–31).
CT=$(curl -s "http://localhost:3000/vuln/a04/seal" \
     -H 'content-type: application/json' \
     -d '{"data":"AAAAAAAAAAAAAAAA\"role\":\"user\",\"z"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["ciphertext"])')

# XOR 'user'→'root' into ciphertext block 1 (offsets 8..11), then unseal.
# The forged block decrypts to "role":"root"; block 1 becomes garbage we discard.
```

The test does exactly this and asserts `"role":"root"` appears in the output.

## Read it

Compare the `vuln` and `safe` routers:
- `Math.random()` → `crypto.randomBytes(32)`.
- returning `password_md5` → a `403`, plus a server-side `verify-password` that
  uses the slow salted `scryptVerify` and does the *same* work for a missing
  user (so timing doesn't reveal which usernames exist).
- `aes-256-cbc` + static IV + no tag → `aes-256-gcm` with a random IV and an
  auth tag, so `decipher.final()` **throws** on any tampered byte.

## Fix it (the ideas, so you can spot them elsewhere)

- **`crypto.randomBytes`, never `Math.random()`**, for anything security-bearing.
- **Never return password material.** Verify server-side, in constant time.
- **Store passwords with a slow salted KDF** (scrypt/argon2/bcrypt), not MD5/SHA.
- **Use authenticated encryption** (AES-GCM, or a library like libsodium).
  Encryption without a MAC is a rewrite primitive, not a security control.

## Prove it

```bash
npm run test:a04
```

## Spot it in review

- `Math.random()`, `Date.now()`, or a counter used to mint a token, id, or nonce.
- Any endpoint that returns a hash, salt, or key — even to admins.
- `createCipheriv('aes-...-cbc'|'...-ctr', ...)` with no separate MAC, a static
  or reused IV, or a decrypt path that trusts whatever comes out.
- Password checks with `===` on a hash, or MD5/SHA-1 in the storage path.

## Read more
<https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/>
