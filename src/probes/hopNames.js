'use strict';

const dns = require('dns');
const net = require('net');

// Reverse-DNS names for the routers on a traced path.
//
// A backbone router's PTR name usually says where it stands:
// `ae3.cph-bb1.telia.net`, `be2376.ccr41.fra03.atlas.cogentco.com`,
// `ae-5.r20.frnkge08.de.bb.gin.ntt.net`. The server reads the city out of that
// name to put the hop on the map in the right city instead of in the middle of
// the country its address block is registered to. The agent only fetches the
// name; reading it is the server's job, so the table of codes can grow without
// redeploying agents.
//
// Traceroute itself still runs with `-n`: letting the binary resolve names
// would make every hop wait on DNS while the trace runs, and slow the live view
// down to the speed of the slowest resolver. Here the lookups run AFTER the
// trace, in parallel, under one overall budget, and a hop whose lookup is slow
// or fails simply has no name.
//
// Only PUBLIC addresses are looked up. Private, loopback, link-local and CGNAT
// hops are the customer's own network: their names say nothing about geography
// and are not the server's to collect.

const LOOKUP_TIMEOUT_MS = 2000;
const TOTAL_BUDGET_MS = 6000;
const CONCURRENCY = 8;
const MAX_NAME = 253;

function isPublicIp(ip) {
  const s = String(ip || '');
  const v = net.isIP(s);
  if (v === 4) {
    const [a, b] = s.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64/10
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    return true;
  }
  if (v === 6) {
    const x = s.toLowerCase();
    if (x === '::1' || x === '::') return false;
    if (/^f[cd]/.test(x)) return false; // ULA fc00::/7
    if (/^fe[89ab]/.test(x)) return false; // link-local fe80::/10
    if (x.startsWith('::ffff:')) return isPublicIp(x.slice(7));
    return true;
  }
  return false;
}

// A PTR answer as the server will get it: lower case, no trailing dot, DNS
// characters only. Anything else is dropped rather than sent on.
function cleanName(name) {
  const s = String(name || '').trim().toLowerCase().replace(/\.$/, '');
  if (!s || s.length > MAX_NAME) return null;
  if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/.test(s)) return null;
  return s;
}

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => { timer = setTimeout(() => resolve(null), ms); }),
  ]).finally(() => clearTimeout(timer));
}

// Adds `hostname` to every hop whose public address has a PTR record. Returns
// the same hops array (mutated in place) so callers can chain it. `reverse` is
// injectable for tests; pass `reverse: null` to skip naming entirely.
async function nameHops(hops, {
  reverse = dns.promises.reverse,
  timeoutMs = LOOKUP_TIMEOUT_MS,
  budgetMs = TOTAL_BUDGET_MS,
  concurrency = CONCURRENCY,
} = {}) {
  if (typeof reverse !== 'function' || !Array.isArray(hops) || !hops.length) return hops;
  // One lookup per distinct address: an ECMP path or a looping trace repeats them.
  const ips = [...new Set(hops.map((h) => h && h.ip).filter(isPublicIp))];
  if (!ips.length) return hops;

  const names = new Map();
  let next = 0;
  async function worker() {
    while (next < ips.length) {
      const ip = ips[next];
      next += 1;
      try {
        // eslint-disable-next-line no-await-in-loop
        const answer = await withTimeout(Promise.resolve().then(() => reverse(ip)), timeoutMs);
        const name = Array.isArray(answer) ? cleanName(answer[0]) : null;
        if (name) names.set(ip, name);
      } catch { /* no PTR, or the resolver failed — the hop stays unnamed */ }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, ips.length) }, () => worker());
  await withTimeout(Promise.all(workers), budgetMs);

  for (const h of hops) {
    if (h && names.has(h.ip)) h.hostname = names.get(h.ip);
  }
  return hops;
}

module.exports = { nameHops, isPublicIp, cleanName, LOOKUP_TIMEOUT_MS, TOTAL_BUDGET_MS };
