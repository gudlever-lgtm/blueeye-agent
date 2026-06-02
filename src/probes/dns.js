'use strict';

const dns = require('dns');
const { clampInt, summarize, fail } = require('./stats');

// DNS-resolution probe: times `count` lookups of `host` and reports success/loss
// + RTT stats. Uses the system resolver by default; `resolver` is injectable so
// tests need no network. A resolver returns either { address } or an array.
async function dnsProbe(spec, { resolver = dns.promises.lookup, now = () => Date.now() } = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  if (!host) return fail('dns', host, 'invalid host');
  const count = clampInt(spec.count, 3, 1, 20);
  const rtts = [];
  let address = null;
  for (let i = 0; i < count; i += 1) {
    const t0 = now();
    try {
      // eslint-disable-next-line no-await-in-loop
      const r = await resolver(host);
      rtts.push(now() - t0);
      if (!address) address = (r && (r.address || (Array.isArray(r) ? r[0] : r))) || null;
    } catch { /* a miss counts toward loss */ }
  }
  return summarize('dns', host, rtts, count, address ? { detail: String(address) } : {});
}

module.exports = { dnsProbe };
