'use strict';
const http = require('node:http');
const { createApp } = require('../app/server');

/**
 * Boot the lab app on an ephemeral port and return a tiny fetch wrapper.
 * `node --test` runs each file in its own process, so each test file gets a
 * fresh in-memory database (migrated + seeded on import of app/db).
 */
function startLab() {
  const server = createApp().listen(0, '127.0.0.1');
  const ready = new Promise((r) => server.once('listening', r));

  async function call(method, path, { json, form, headers = {} } = {}) {
    await ready;
    const url = `http://127.0.0.1:${server.address().port}${path}`;
    const init = { method, headers: { ...headers }, redirect: 'manual' };
    if (json !== undefined) { init.headers['content-type'] = 'application/json'; init.body = JSON.stringify(json); }
    if (form !== undefined) { init.headers['content-type'] = 'application/x-www-form-urlencoded'; init.body = new URLSearchParams(form).toString(); }
    const res = await fetch(url, init);
    const text = await res.text();
    let body; try { body = JSON.parse(text); } catch { body = text; }
    return { status: res.status, body, text, headers: res.headers };
  }
  return {
    get: (p, o) => call('GET', p, o),
    post: (p, o) => call('POST', p, o),
    put: (p, o) => call('PUT', p, o),
    del: (p, o) => call('DELETE', p, o),
    port: () => server.address().port,
    stop: () => server.close(),
  };
}

/**
 * Stand up a throwaway "internal" HTTP service on 127.0.0.1 for the SSRF lab.
 * Loopback counts as private, so the SAFE guard blocks it while the VULN route
 * reaches it — exactly the Docker behaviour, without needing Docker in tests.
 */
function startInternalService(handler) {
  const server = http.createServer(handler || ((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ secret: 'FLAG{internal-only}', path: req.url }));
  }));
  server.listen(0, '127.0.0.1');
  const ready = new Promise((r) => server.once('listening', r));
  return {
    url: async () => { await ready; return `http://127.0.0.1:${server.address().port}`; },
    stop: () => server.close(),
  };
}

module.exports = { startLab, startInternalService };
