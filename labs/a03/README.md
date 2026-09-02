# A03:2025 — Software Supply Chain Failures

> NEW for 2025, and #1 in the community survey. 2021's "Vulnerable and Outdated
> Components" widens into the whole supply chain: not just "is a dependency old"
> but "what did I actually install, what ran code on my build machine, and can I
> reproduce this build tomorrow?"

**The one-sentence version:** you write down a handful of dependencies and
`npm install` fetches a hundred — any one of which can run code at install time,
and any one of which is your problem when it's compromised.

Source files: [`app/routes/a03-supply-chain.js`](../../app/routes/a03-supply-chain.js)
· Tests: [`tests/a03.test.js`](../../tests/a03.test.js)
· CI: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)

---

## Break it

This lab doesn't exploit anything — the exploit is the arithmetic. Start the app
(`npm start`) and make the invisible visible:

```bash
# You declared 3 dependencies. How big is your trust boundary really?
curl -s "http://localhost:3000/vuln/a03/inventory" | python3 -m json.tool
#   directDependencies:               3
#   packagesActuallyInstalled:        > 100
#   packagesThatRunCodeAtInstallTime: preinstall/install/postinstall scripts

# The two postures, side by side:
curl -s "http://localhost:3000/vuln/a03/resolution"   # npm install + caret ranges
curl -s "http://localhost:3000/safe/a03/resolution"   # npm ci + a locked, pinned tree
```

## Read it

`/inventory` reads `package.json`, then walks `node_modules` and counts what is
*actually* on disk (scoped packages included) and which packages declare
install-time lifecycle scripts. Both `/vuln` and `/safe` serve the same
inventory — the facts don't change. What changes is the discipline: `/resolution`
contrasts `npm install` against a caret range with `npm ci` against a lockfile.

## Fix it (the ideas, so you can spot them elsewhere)

- **Commit a lockfile and install from it.** `npm ci` installs the *exact*
  locked versions and verifies each integrity hash; a mismatch fails the build.
  `npm install` may resolve `^4.21.1` to whatever was published five minutes ago.
- **`--ignore-scripts` in CI** so install-time code doesn't run at all.
- **Pin your GitHub Actions to a commit SHA**, not a mutable `@v4` tag — the CI
  file itself is part of the supply chain.
- **Generate an SBOM** (`npm run sbom`) and **audit** (`npm audit`) in the
  pipeline so a known-vulnerable transitive dep fails the build, not production.

## Prove it

```bash
npm run test:a03
```

The test asserts the tree is what you think (3 direct deps, >20 installed), that
every direct dependency is pinned in `package-lock.json` with a version and an
integrity hash, and that CI uses `npm ci` and never `npm install`.

## Spot it in review

- A PR that changes `package.json` but not `package-lock.json` (or vice versa).
- CI that runs `npm install` instead of `npm ci`.
- GitHub Actions pinned to `@v4` / `@main` instead of a commit SHA.
- A new dependency with an install/postinstall script, or a typo-squatted name.
- No lockfile committed at all.

## Read more
<https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
