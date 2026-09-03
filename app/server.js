'use strict';
/**
 * OWASP Top 10:2025 workshop lab — application entry point.
 *
 * Every category is mounted twice:
 *     /vuln/aNN/...   the broken version
 *     /safe/aNN/...   the same feature, fixed
 * Send the same request to both and diff the response. The route source files
 * put the two implementations side by side with comments.
 *
 * /metrics is scraped by Prometheus; Grafana graphs it (see the A09 lab).
 *
 * !! This application is DELIBERATELY VULNERABLE. Run it on localhost / the
 *    Docker network only. Never deploy it or point it at real data. !!
 */
const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const { register, httpMetricsMiddleware } = require('./metrics');
const { renderFeed, renderProfile } = require('./web/render');
const labs = require('./web/labs');

const CATEGORIES = [
  ['a01', 'Broken Access Control',                 'a01-broken-access-control', 'up',   '#1 · SSRF folded in'],
  ['a02', 'Security Misconfiguration',             'a02-security-misconfiguration', 'up', '#5 → #2 · biggest mover'],
  ['a03', 'Software Supply Chain Failures',        'a03-supply-chain',          'new',  'expanded · survey #1'],
  ['a04', 'Cryptographic Failures',                'a04-cryptographic-failures','', '#2 → #4'],
  ['a05', 'Injection',                             'a05-injection',             '', '#3 → #5 · XSS here'],
  ['a06', 'Insecure Design',                       'a06-insecure-design',       '', '#4 → #6'],
  ['a07', 'Authentication Failures',               'a07-authentication-failures','', '#7 · renamed'],
  ['a08', 'Software or Data Integrity Failures',   'a08-integrity-failures',    '', '#8'],
  ['a09', 'Security Logging & Alerting Failures',  'a09-logging-alerting',      'up', '#9 · Monitoring→Alerting'],
  ['a10', 'Mishandling of Exceptional Conditions', 'a10-exceptional-conditions','new', 'brand new'],
];

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(httpMetricsMiddleware);
  app.use('/static', express.static(path.join(__dirname, 'public')));

  for (const [code, , file] of CATEGORIES) {
    try {
      // eslint-disable-next-line import/no-dynamic-require
      const { vuln, safe } = require(path.join(__dirname, 'routes', file));
      app.use(`/vuln/${code}`, vuln);
      app.use(`/safe/${code}`, safe);
    } catch (err) {
      // A route module failed to load (e.g. mid-edit). Mount a placeholder so
      // the rest of the app still boots, and surface the reason.
      const boom = express.Router();
      boom.use((req, res) => res.status(500).json({ error: `route ${code} failed to load`, detail: err.message }));
      app.use(`/vuln/${code}`, boom);
      app.use(`/safe/${code}`, boom);
      console.error(`route ${code} failed to load: ${err.message}`);
    }
  }

  app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // Reset the lab data (re-seed) without restarting — handy during a demo.
  app.post('/reset', (req, res) => {
    const { openDatabase } = require('./db');
    try { openDatabase(); } catch { /* singleton already open */ }
    res.json({ ok: true, note: 'file-backed DB persists; use `npm run db:reset` for a full wipe' });
  });

  // ---- LinkedIn-style front end ----
  app.get('/', (req, res) => {
    res.type('html').send(renderFeed(labs.load()));
  });

  app.get('/lab/:code', (req, res) => {
    const all = labs.load();
    const lab = all.find((l) => l.code === req.params.code);
    if (!lab) return res.status(404).type('html').send('<p>No such lab. <a href="/">Back to feed</a></p>');
    res.type('html').send(renderProfile(lab));
  });

  return app;
}

// Serve HTTPS when a cert/key pair is available (mkcert on the host, or the
// self-signed fallback the Docker entrypoint generates). Falls back to HTTP so
// a bare `node app/server.js` still works with no setup. HTTPS is what makes
// the Secure-cookie (A02) and HSTS demos behave the way a real site does.
function tlsCredentials() {
  const cert = process.env.TLS_CERT || path.join(__dirname, '..', 'certs', 'localhost.pem');
  const key = process.env.TLS_KEY || path.join(__dirname, '..', 'certs', 'localhost-key.pem');
  if (fs.existsSync(cert) && fs.existsSync(key)) {
    try { return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) }; }
    catch { return null; }
  }
  return null;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const app = createApp();
  const creds = tlsCredentials();
  const scheme = creds ? 'https' : 'http';
  const server = creds ? require('node:https').createServer(creds, app) : app;
  server.listen(port, host, () => {
    const shown = host === '0.0.0.0' ? 'localhost' : host;
    console.log(`\n  OWASP Top 10:2025 lab → ${scheme}://${shown}:${port}`);
    if (scheme === 'http') {
      console.log('  (plain HTTP — run `npm run tls:setup` for a trusted https://localhost)');
    }
    console.log('  Deliberately vulnerable. Metrics at /metrics.\n');
  });
}

module.exports = { createApp, CATEGORIES };
