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

// Collects this host's own IPv4 SUBNETS (network CIDRs), derived from each
// interface's cidr (e.g. "192.168.1.34/24" → "192.168.1.0/24"). Used as the
// default active-discovery scope when an admin leaves the scope blank: "scan the
// segment this agent is on". Loopback / link-local / IPv6 are skipped, and a /31
// or /32 is dropped (nothing useful to sweep). Deduped. Injectable for tests.
function collectLocalCidrs({ networkInterfaces = () => os.networkInterfaces() } = {}) {
  const out = new Set();
  let ifaces;
  try {
    ifaces = networkInterfaces() || {};
  } catch {
    return [];
  }
  for (const list of Object.values(ifaces)) {
    for (const a of Array.isArray(list) ? list : []) {
      if (!a || a.internal || a.family !== 'IPv4' || !a.cidr) continue;
      const addr = String(a.address || '');
      if (addr.startsWith('169.254.')) continue; // link-local
      const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(String(a.cidr));
      if (!m) continue;
      const prefix = Number(m[2]);
      if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) continue; // sane sweepable range
      // Network address for the prefix (mask off the host bits).
      const parts = m[1].split('.').map(Number);
      const ipInt = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const net = (ipInt & mask) >>> 0;
      const network = `${(net >>> 24) & 255}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}`;
      out.add(`${network}/${prefix}`);
    }
  }
  return [...out];
}

module.exports = { collectLocalIps, collectLocalCidrs };
