'use strict';
/**
 * The internal service the SSRF lab reaches (A01, CWE-918).
 *
 * In Docker this container is NOT published to the host — it only exists on the
 * private compose network as `internal-api`. A user of the lab app cannot open
 * http://internal-api:8081 in their browser. But the lab app can, and the
 * vulnerable "fetch this URL" feature will happily proxy the attacker there.
 *
 * It also answers on the cloud-metadata path, so the classic
 *   http://169.254.169.254/latest/meta-data/iam/security-credentials/...
 * scenario can be demonstrated (compose aliases this host to the container).
 */
const http = require('node:http');

const CREDS = {
  Code: 'Success',
  Type: 'AWS-HMAC',
  AccessKeyId: 'EXAMPLE-lab-access-key-id-only',
  SecretAccessKey: 'lab-fake-secret-do-not-use-000000000000',
  Token: 'FQoGZXIvYXdzEExampleSessionTokenDoNotUse==',
  Expiration: '2030-01-01T00:00:00Z',
};

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const json = (obj, code = 200) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj, null, 2)); };

  if (url === '/' || url === '/health') return json({ service: 'internal-api', note: 'network-internal only', hint: 'try /latest/meta-data/iam/security-credentials/lab-role or /internal/admin/flag' });

  // Cloud metadata service imitation.
  if (url === '/latest/meta-data/iam/security-credentials/') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('lab-role'); }
  if (url === '/latest/meta-data/iam/security-credentials/lab-role') return json(CREDS);

  // Internal admin surface that should never be reachable from outside.
  if (url === '/internal/admin/flag') return json({ flag: 'FLAG{ssrf-reached-the-internal-service}', users: ['root', 'ci-deploy', 'backup'] });
  if (url === '/internal/admin/users') return json({ users: [{ name: 'root', keys: 3 }, { name: 'ci-deploy', keys: 1 }] });

  json({ error: 'not found', path: url }, 404);
});

const PORT = Number(process.env.PORT) || 8081;
server.listen(PORT, () => console.log(`internal-api listening on ${PORT} (network-internal)`));
