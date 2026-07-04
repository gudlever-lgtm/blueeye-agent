'use strict';

const { httpExecutor } = require('./http');
const { tcpExecutor } = require('./tcp');
const { dnsExecutor } = require('./dns');
const { icmpExecutor } = require('./icmp');

const EXECUTORS = { http: httpExecutor, tcp: tcpExecutor, dns: dnsExecutor, icmp: icmpExecutor };

// Runs one transaction test and returns a result stamped for the WS ingest:
//   { test_id, time, status, latency_ms, step_timings?, step_failed?, detail? }
// Never throws — an unknown type or an executor error resolves to a status:'error'
// result so a single bad test can't crash the agent.
async function runTransaction(test, deps = {}) {
  const type = String((test && test.type) || '').toLowerCase();
  const time = new Date().toISOString();
  const base = { test_id: test && test.id, time };
  const fn = EXECUTORS[type];
  if (!fn) return { ...base, status: 'error', latency_ms: 0, detail: { phase: 'error', errno: 'UNKNOWN_TYPE' } };
  try {
    const r = await fn(test, deps);
    return { ...base, ...r };
  } catch (err) {
    return { ...base, status: 'error', latency_ms: 0, detail: { phase: 'error', errno: (err && err.code) || 'EXEC_ERROR' } };
  }
}

module.exports = { runTransaction, EXECUTORS };
