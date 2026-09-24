'use strict';

const { httpExecutor } = require('./http');
const { tcpExecutor } = require('./tcp');
const { dnsExecutor } = require('./dns');
const { icmpExecutor } = require('./icmp');

const EXECUTORS = { http: httpExecutor, tcp: tcpExecutor, dns: dnsExecutor, icmp: icmpExecutor };

// Runs one transaction test and returns a result stamped for the WS ingest:
//   { test_id, time, status, latency_ms, step_timings?, step_phases?, step_failed?, detail? }
// Never throws — an unknown type or an executor error resolves to a status:'error'
// result so a single bad test can't crash the agent.
//
// ONE WIRE SHAPE FOR PHASES. The http executor runs several steps and produces
// `step_phases` itself; tcp/dns are single-step and return a bare `phases`
// object. Normalising here means the server, the schema and the dashboard see
// an array in every case, and the difference stays where it belongs — in the
// executor that has steps and the ones that do not.
async function runTransaction(test, deps = {}) {
  const type = String((test && test.type) || '').toLowerCase();
  const time = new Date().toISOString();
  const base = { test_id: test && test.id, time };
  const fn = EXECUTORS[type];
  if (!fn) return { ...base, status: 'error', latency_ms: 0, detail: { phase: 'error', errno: 'UNKNOWN_TYPE' } };
  try {
    const r = await fn(test, deps);
    return { ...base, ...normalisePhases(r) };
  } catch (err) {
    return { ...base, status: 'error', latency_ms: 0, detail: { phase: 'error', errno: (err && err.code) || 'EXEC_ERROR' } };
  }
}

// Lifts a single-step executor's `phases` into the `step_phases` array. A result
// that already carries `step_phases` is left alone; one with neither (icmp, and
// any executor added later that cannot observe a handshake) stays as it is —
// an absent breakdown must not become an array of nulls that looks measured.
function normalisePhases(result) {
  if (!result || typeof result !== 'object') return result;
  if (Array.isArray(result.step_phases)) {
    const { phases, ...rest } = result;
    return rest;
  }
  if (result.phases && typeof result.phases === 'object') {
    const { phases, ...rest } = result;
    return { ...rest, step_phases: [phases] };
  }
  return result;
}

module.exports = { runTransaction, EXECUTORS };
