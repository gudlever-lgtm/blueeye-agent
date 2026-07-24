'use strict';

const os = require('os');

// Collects this host's own IP addresses so the server can resolve a flow's
// src/dst IP back to the monitored host it belongs to (the service dependency
// graph needs "which agent IS this IP", not just "which agent saw it").
//
// Metadata only — addresses of this machine's own interfaces. Loopback and
// link-local addresses are skipped (never a useful host identity); everything
// else (including RFC1918 LAN addresses, which is exactly what we want to match)
// is kept. Injectable for tests.
function collectLocalIps({ networkInterfaces = () => os.networkInterfaces() } = {}) {
  const out = new Set();
  let ifaces;
  try {
    ifaces = networkInterfaces() || {};
  } catch {
    return [];
  }
  for (const list of Object.values(ifaces)) {
    for (const a of Array.isArray(list) ? list : []) {
      if (!a || !a.address || a.internal) continue; // skip loopback / internal
      const addr = String(a.address);
      // Skip IPv6 link-local (fe80::/10, may carry a %zone suffix).
      if (a.family === 'IPv6' && /^fe80:/i.test(addr)) continue;
      // Skip IPv4 link-local (169.254.0.0/16).
      if (a.family === 'IPv4' && addr.startsWith('169.254.')) continue;
      out.add(addr);
    }
  }
  return [...out];
}

module.exports = { collectLocalIps };
