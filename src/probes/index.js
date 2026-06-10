'use strict';

const { tcpProbe } = require('./tcp');
const { dnsProbe } = require('./dns');
const { pingProbe } = require('./ping');
const { traceroute } = require('./traceroute');
const { httpProbe } = require('./http');
const { curlProbe } = require('./curl');
const { pageloadProbe } = require('./pageload');
const { transactionProbe } = require('./transaction');

const RUNNERS = { tcp: tcpProbe, dns: dnsProbe, ping: pingProbe, traceroute, http: httpProbe, curl: curlProbe, pageload: pageloadProbe, transaction: transactionProbe };

// Runs one probe by spec.type and returns a normalized result stamped with `ts`.
// Never throws: an unknown type or a runner error resolves to an ok:false result
// so a bad probe can't crash the agent. `deps` lets tests inject per-type fakes:
//   runProbe({ type:'tcp', host, port }, { tcp: { connect } })
async function runProbe(spec, deps = {}) {
  const type = String((spec && spec.type) || '').toLowerCase();
  const target = String((spec && (spec.host || spec.target)) || '');
  const base = { ts: new Date().toISOString() };
  const runner = RUNNERS[type];
  if (!runner) return { ...base, type: type || 'unknown', target, ok: false, error: `unknown probe type "${type}"` };
  try {
    return { ...base, ...(await runner(spec, deps[type] || {})) };
  } catch (err) {
    return { ...base, type, target, ok: false, error: err.message };
  }
}

module.exports = { runProbe, PROBE_TYPES: Object.keys(RUNNERS) };
