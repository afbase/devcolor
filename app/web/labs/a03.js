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
    text: `Proud of the DepDrop team 🙌 We keep it lean — our package.json lists just a handful of dependencies. Minimalism is a security posture!

Our build is dead simple too: "npm install" and go. Fresh resolve every time keeps us on the latest patches automatically. Why pin versions when the ecosystem moves this fast? 🤷

Someone on my team asked about our "lockfile discipline" and honestly I told them lockfiles are just cache. We move faster without the ceremony.

#supplychain #opensource #startup #buildinpublic #leanstack`,
  },
  profile: {
    headline: 'Founder & CEO @ DepDrop · "we only have a few dependencies"',
    about: `I tell everyone DepDrop runs on a tiny, hand-picked set of dependencies. It's my favorite line at conferences.

Call my bluff on the bench below. Ask /inventory how many packages I *wrote down* versus how many npm actually dropped into node_modules — and how many of those run code on my build machine the instant I install. Then compare /resolution on both sides: my "npm install and ship it" posture versus the pinned, locked, "npm ci --ignore-scripts" one I keep meaning to adopt.`,
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
        expect: {
          vuln: '"npm install", respectsLockfile:false — a caret range lets a freshly published/compromised version in silently',
          safe: '"npm ci --ignore-scripts", every direct dependency pinned to an exact version + integrity hash',
        },
      },
    ],
  },
};
