'use strict';
const client = require('prom-client');

/**
 * The observability backbone. Prometheus scrapes /metrics; Grafana graphs it.
 *
 * A09 (Security Logging & Alerting Failures) is taught with these counters:
 * the /vuln endpoints deliberately DON'T touch them, so an attack is invisible
 * in Grafana; the /safe endpoints do, so the same attack shows up as a spike
 * and trips a Prometheus alert.
 */
const register = new client.Registry();
register.setDefaultLabels({ app: 'owasp-lab' });
client.collectDefaultMetrics({ register });

const httpRequests = new client.Counter({
  name: 'lab_http_requests_total',
  help: 'HTTP requests handled, by method, route group and status class.',
  labelNames: ['method', 'group', 'status'],
  registers: [register],
});

const authAttempts = new client.Counter({
  name: 'lab_auth_attempts_total',
  help: 'Authentication attempts by result (success, failure, lockout, breached).',
  labelNames: ['result'],
  registers: [register],
});

const accessDenied = new client.Counter({
  name: 'lab_access_denied_total',
  help: 'Access-control denials (A01).',
  labelNames: ['resource'],
  registers: [register],
});

const ssrfAttempts = new client.Counter({
  name: 'lab_ssrf_fetch_total',
  help: 'Outbound URL fetches by result (allowed, blocked).',
  labelNames: ['result'],
  registers: [register],
});

const securityAlerts = new client.Counter({
  name: 'lab_security_alerts_total',
  help: 'Security alerts raised (e.g. suspected brute force).',
  labelNames: ['kind'],
  registers: [register],
});

/** Express middleware: count every response by route group and status class. */
function httpMetricsMiddleware(req, res, next) {
  res.on('finish', () => {
    const group = (req.baseUrl || req.path || '/').split('/').slice(0, 3).join('/') || '/';
    httpRequests.inc({ method: req.method, group, status: `${Math.floor(res.statusCode / 100)}xx` });
  });
  next();
}

module.exports = {
  register, client,
  metrics: { httpRequests, authAttempts, accessDenied, ssrfAttempts, securityAlerts },
  httpMetricsMiddleware,
};
