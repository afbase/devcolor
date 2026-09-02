'use strict';
// Registry of lab front-end modules (persona + feed post + profile + bench).
// Resilient: a missing/broken module becomes a placeholder so the feed still
// renders while the team is still building one out.
const path = require('node:path');

const ORDER = [
  ['a01', 'Broken Access Control', '#1 · SSRF folded in'],
  ['a02', 'Security Misconfiguration', '▲ #5 → #2'],
  ['a03', 'Software Supply Chain Failures', 'NEW · survey #1'],
  ['a04', 'Cryptographic Failures', '▼ #2 → #4'],
  ['a05', 'Injection', '▼ #3 → #5 · XSS here'],
  ['a06', 'Insecure Design', '▼ #4 → #6'],
  ['a07', 'Authentication Failures', '#7 · renamed'],
  ['a08', 'Software or Data Integrity Failures', '#8'],
  ['a09', 'Security Logging & Alerting Failures', '#9 · Monitoring→Alerting'],
  ['a10', 'Mishandling of Exceptional Conditions', 'NEW'],
];

function placeholder(code, title, rank) {
  return {
    code, title, rank,
    persona: { name: title, title: `OWASP ${code.toUpperCase()}`, company: title, avatar: code.toUpperCase().slice(1), color: '#5f6b7a', location: 'The Internet', connections: '500+' },
    post: { time: '1h', text: `Profile for ${title} is being set up.`, headline: title, cta: 'Coming online shortly', reactions: 0, comments: 0, reposts: 0 },
    profile: { headline: title, about: 'This lab profile is being built.', highlights: [] },
    bench: { intro: 'Bench coming online.', actions: [] },
  };
}

function load() {
  return ORDER.map(([code, title, rank]) => {
    try {
      const m = require(path.join(__dirname, code));
      return Object.assign({ code, title, rank }, m);
    } catch (err) {
      console.error(`lab module ${code} not loaded: ${err.message}`);
      return placeholder(code, title, rank);
    }
  });
}

module.exports = { load, ORDER };
