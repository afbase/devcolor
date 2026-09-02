'use strict';
const dns = require('node:dns').promises;
const net = require('node:net');

/**
 * SSRF defence (A01, CWE-918). The vulnerable routes fetch a user URL directly.
 * The safe routes call assertPublicUrl() first, which:
 *   1. allows only http/https,
 *   2. resolves the hostname to its actual IPs, and
 *   3. rejects any IP in a loopback / private / link-local / reserved range.
 *
 * Resolving BEFORE fetching is what defeats DNS rebinding — a hostname that
 * points at 169.254.169.254 (the cloud metadata service) or 10.x is blocked
 * even though the string looks innocuous.
 */

function ipIsPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;                         // 10.0.0.0/8
    if (a === 127) return true;                        // loopback
    if (a === 0) return true;                          // 0.0.0.0/8
    if (a === 169 && b === 254) return true;           // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a === 192 && b === 168) return true;           // 192.168.0.0/16
    if (a >= 224) return true;                         // multicast / reserved
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;             // loopback / unspecified
  if (lower.startsWith('fe80') || lower.startsWith('fc') || lower.startsWith('fd')) return true; // link-local / ULA
  if (lower.startsWith('::ffff:')) return ipIsPrivate(lower.slice(7)); // IPv4-mapped
  return false;
}

/**
 * Throws with a descriptive message if `rawUrl` is not a safe public target.
 * Returns the parsed URL and its resolved public IPs on success.
 */
async function assertPublicUrl(rawUrl, { allowHosts } = {}) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error('not a valid URL'); }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`scheme ${url.protocol} is not allowed (http/https only)`);
  }

  // Optional strict allow-list — the strongest control when you know your targets.
  if (allowHosts && !allowHosts.includes(url.hostname)) {
    throw new Error(`host ${url.hostname} is not on the allow-list`);
  }

  // A literal private IP in the URL never even needs DNS.
  if (net.isIP(url.hostname) && ipIsPrivate(url.hostname)) {
    throw new Error(`host ${url.hostname} is a private/reserved address`);
  }

  const resolved = net.isIP(url.hostname)
    ? [url.hostname]
    : (await dns.lookup(url.hostname, { all: true })).map((r) => r.address);

  for (const ip of resolved) {
    if (ipIsPrivate(ip)) {
      throw new Error(`host ${url.hostname} resolves to private/reserved address ${ip}`);
    }
  }
  return { url, resolved };
}

module.exports = { assertPublicUrl, ipIsPrivate };
