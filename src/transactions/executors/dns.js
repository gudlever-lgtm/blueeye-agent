'use strict';

const dns = require('dns');

// DNS-resolution test: resolves target with the configured record type and
// (optionally) checks the answer contains an expected substring. `resolver` is
// injectable (dns.promises-shaped) so tests don't hit a real resolver.
async function dnsExecutor(test, { resolver = dns.promises, now = () => Date.now() } = {}) {
  const cfg = test.config || {};
  const host = test.target;
  const record = String(cfg.record || 'A').toUpperCase();
  const expect = cfg.expect != null && cfg.expect !== '' ? String(cfg.expect) : null;
  const t0 = now();
  try {
    const answer = await resolver.resolve(host, record);
    const flat = JSON.stringify(answer);
    if (expect && !flat.includes(expect)) {
      return { status: 'fail', latency_ms: now() - t0, detail: { phase: 'keyword', errno: 'NO_MATCH' } };
    }
    return { status: 'ok', latency_ms: now() - t0 };
  } catch (err) {
    const code = err && err.code ? String(err.code) : '';
    const status = code === 'ETIMEDOUT' ? 'timeout' : (code === 'ENOTFOUND' || code === 'ENODATA' ? 'fail' : 'error');
    return { status, latency_ms: now() - t0, detail: { phase: status === 'timeout' ? 'timeout' : 'dns', errno: code || 'EDNS' } };
  }
}

module.exports = { dnsExecutor };
