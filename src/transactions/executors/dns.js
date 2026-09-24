'use strict';

const dns = require('dns');

const TIMEOUT_CODES = new Set(['ETIMEOUT', 'ETIMEDOUT']);

// A dns test has one phase. Same key set as the other executors so the
// dashboard renders every transaction type with one component.
function dnsPhases(ms) {
  return { dns: Math.max(0, Math.round(ms)), tcp: null, tls: null, ttfb: null, transfer: null };
}

// DNS-resolution test: resolves target with the configured record type and
// (optionally) checks the answer contains an expected substring. `resolver` is
// injectable (dns.promises-shaped) so tests don't hit a real resolver.
//
// `phases` exists here too, with everything in `dns`, so a dashboard can render
// one waterfall for every transaction type instead of special-casing this one.
// A dns test IS its resolution phase — the shape stays uniform, and the zeros
// are honest rather than padding.
async function dnsExecutor(test, { resolver = dns.promises, now = () => Date.now() } = {}) {
  const cfg = test.config || {};
  const host = test.target;
  const record = String(cfg.record || 'A').toUpperCase();
  const expect = cfg.expect != null && cfg.expect !== '' ? String(cfg.expect) : null;
  const t0 = now();
  try {
    const answer = await resolver.resolve(host, record);
    const ms = now() - t0;
    const flat = JSON.stringify(answer);
    if (expect && !flat.includes(expect)) {
      return { status: 'fail', latency_ms: ms, phases: dnsPhases(ms), detail: { phase: 'keyword', errno: 'NO_MATCH' } };
    }
    return { status: 'ok', latency_ms: ms, phases: dnsPhases(ms) };
  } catch (err) {
    const code = err && err.code ? String(err.code) : '';
    // Node's resolver reports a timeout as 'ETIMEOUT' (dns.TIMEOUT), not the
    // socket-level 'ETIMEDOUT' — checking only the latter filed every DNS
    // timeout under 'error'. Both are accepted, so an injected resolver that
    // speaks the socket dialect is classified the same way.
    const status = TIMEOUT_CODES.has(code) ? 'timeout' : (code === 'ENOTFOUND' || code === 'ENODATA' ? 'fail' : 'error');
    const ms = now() - t0;
    return { status, latency_ms: ms, phases: dnsPhases(ms), detail: { phase: status === 'timeout' ? 'timeout' : 'dns', errno: code || 'EDNS' } };
  }
}

module.exports = { dnsExecutor };
