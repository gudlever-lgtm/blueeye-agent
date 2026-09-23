'use strict';

const dns = require('dns');
const { clampInt, summarize, fail } = require('./stats');

// The resolver's error code, kept short and in the shape Node gives it
// (ENOTFOUND, ETIMEOUT, ESERVFAIL, ECONNREFUSED, EAI_AGAIN …). A thrown value
// with no code is still a failure, and 'EUNKNOWN' says so rather than null,
// which is reserved for "nothing failed".
function errorCodeOf(err) {
  const code = err && err.code != null ? String(err.code).trim() : '';
  return /^[A-Za-z0-9_]{1,32}$/.test(code) ? code.toUpperCase() : 'EUNKNOWN';
}

// DNS-resolution probe: times `count` lookups of `host` and reports success/loss
// + RTT stats. Uses the system resolver by default; `resolver` is injectable so
// tests need no network. A resolver returns either { address } or an array.
//
// `errorCode` is the code of the LAST attempt that failed, or null when none
// did. Loss alone cannot tell "the name does not exist" (ENOTFOUND) from "the
// resolver did not answer" (ETIMEOUT) or "it answered SERVFAIL" — three faults
// with three different owners.
async function dnsProbe(spec, { resolver = dns.promises.lookup, now = () => Date.now() } = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  if (!host) return { ...fail('dns', host, 'invalid host'), errorCode: null };
  const count = clampInt(spec.count, 3, 1, 20);
  const rtts = [];
  let address = null;
  let errorCode = null;
  for (let i = 0; i < count; i += 1) {
    const t0 = now();
    try {
      // eslint-disable-next-line no-await-in-loop
      const r = await resolver(host);
      rtts.push(now() - t0);
      if (!address) address = (r && (r.address || (Array.isArray(r) ? r[0] : r))) || null;
    } catch (err) {
      // A miss counts toward loss; its code says what kind of miss it was.
      errorCode = errorCodeOf(err);
    }
  }
  return summarize('dns', host, rtts, count, { ...(address ? { detail: String(address) } : {}), errorCode });
}

module.exports = { dnsProbe, errorCodeOf };
