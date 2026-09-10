'use strict';
// A03:2025 — Software Supply Chain Failures. Nothing is exploited here; the lab
// makes the invisible visible. You write down a few dependencies and npm fetches
// a hundred, any of which can run code at install time. The persona is a
// influencer-founder who brags about "minimal dependencies" without ever
// counting what actually landed in node_modules.
module.exports = {
  persona: {
    name: 'Skylar Vance',
    title: 'Founder & CEO at DepDrop',
    company: 'DepDrop',
    avatar: 'SV',
    color: '#6d28d9',
    banner: 'linear-gradient(120deg,#2e1065,#6d28d9 60%,#a78bfa)',
    location: 'San Francisco Bay Area',
    connections: '18,400',
  },
  post: {
    time: '1d',
    reactions: 402, comments: 118, reposts: 57,
    headline: 'DepDrop: we keep our dependency footprint tiny 🌱',
    cta: 'Count the packages you actually trust',
    summary: `The dependencies you didn't write are still code that runs on your machine. Unpinned version ranges, install-time lifecycle scripts, and a sprawling transitive tree mean a plain "npm install" can quietly pull in — and execute — far more than what's listed in package.json.`,
  },
  profile: {
    headline: 'Founder & CEO @ DepDrop · "we only have a few dependencies"',
    about: `Software supply chain failures come from trusting code you didn't write and can't fully see. Every dependency — and every dependency of that dependency — can execute code on your machine, whether through an install-time lifecycle script or the package itself. Unpinned version ranges and unaudited lockfiles mean the code that actually ships can quietly differ from what a developer reviewed.

The handful of packages listed in package.json is rarely the real picture; the transitive tree that npm resolves underneath it usually is.

Try it below: compare how many packages were actually declared against how many npm actually installed, then compare a loose "npm install" against a pinned, locked, script-free "npm ci --ignore-scripts".`,
    highlights: ['Transitive dependency sprawl', 'Install-time lifecycle scripts', 'Unpinned caret ranges', 'npm install vs npm ci', 'Lockfile discipline'],
  },
  bench: {
    intro: 'DepDrop\'s real dependency tree, measured live. Both sides serve the same facts — the lesson is the numbers, and the discipline around them.',
    actions: [
      {
        id: 'inventory',
        title: 'Count what you actually installed',
        description: 'Scans the live node_modules. Compare directDependencies (what you wrote down) with packagesActuallyInstalled (what npm fetched), and see how many run code at install time.',
        method: 'GET', path: '/inventory',
        hint: 'Both sides return the same tree — that is the point. transitiveMultiplier is your real trust boundary.',
        code: {
          lang: 'js',
          src: { vuln: { anchor: 'function scanNodeModules' } },
          intro: 'The risk isn\'t one line of code — it\'s how many packages (and install scripts) you actually trust. This is the measurement, served identically on both sides.',
          vulnLabel: '🔎 What actually landed in node_modules',
          vuln: `// walk node_modules; count what's really on disk and flag install-time scripts
function scanNodeModules() {
  let installed = 0;
  const runsCodeAtInstall = [];
  for (const name of fs.readdirSync(NODE_MODULES)) {
    installed += 1;
    const p = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const s = p.scripts || {};
    // preinstall/install/postinstall run code the MOMENT you npm install
    if (s.preinstall || s.install || s.postinstall) runsCodeAtInstall.push(name);
  }
  return { installed, runsCodeAtInstall };
}
// directDependencies (what you wrote down) vs packagesActuallyInstalled (what npm fetched)`,
          note: 'You audited a handful of names; your real trust boundary is every package on disk, and every one of them that runs code at install time.',
        },
        expect: {
          vuln: 'directDependencies is small; packagesActuallyInstalled is much larger, with N packages running lifecycle scripts',
          safe: 'identical numbers — the facts of the tree don\'t change with route',
        },
      },
      {
        id: 'resolution',
        title: 'Compare the install posture',
        description: 'How the same tree gets resolved. The vuln posture uses caret ranges + `npm install` (non-reproducible). The safe posture pins to the lockfile with integrity hashes.',
        method: 'GET', path: '/resolution',
        hint: 'vuln: respectsLockfile:false, example resolves to "whatever is newest". safe: `npm ci --ignore-scripts`, every direct dep pinned + integrity-checked.',
        code: {
          lang: 'js',
          intro: 'Same dependency tree, two install postures. Reproducibility is the security property.',
          vuln: `// insecure posture: caret ranges + \`npm install\` on every build
vuln.get('/resolution', (req, res) => res.json({
  installCommand: 'npm install',
  respectsLockfile: false,
  example: { declared: 'express: "^4.21.1"',
             mayResolveTo: '4.21.1 … 4.99.99, whatever is newest at build time' },
}));
// a caret range + \`npm install\` lets a freshly published/compromised version in silently`,
          safe: `// secure posture: install the EXACT locked versions, verify integrity, no install scripts
safe.get('/resolution', (req, res) => res.json({
  installCommand: 'npm ci --ignore-scripts',
  respectsLockfile: true,
  // each direct dep pinned to an exact version + integrity hash; a mismatch fails the build
}));`,
        },
        expect: {
          vuln: '"npm install", respectsLockfile:false — a caret range lets a freshly published/compromised version in silently',
          safe: '"npm ci --ignore-scripts", every direct dependency pinned to an exact version + integrity hash',
        },
      },
    ],
  },
};
