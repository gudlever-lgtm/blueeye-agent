'use strict';

const net = require('net');
const { clampInt, summarize, fail } = require('./stats');

// Which kind of "no" a failed connect was. They are different faults with
// different owners, and loss alone cannot tell them apart:
//   refused      — the host answered with a RST: it is up, nothing listens
//                  on the port (or a firewall rejects rather than drops);
//   timeout      — nothing came back at all: a silent drop, a dead host, or
//                  a path that eats SYNs;
//   unreachable  — the local stack or a router said there is no way there;
//   error        — anything else (name resolution, a local socket error).
const UNREACHABLE_CODES = new Set(['EHOSTUNREACH', 'ENETUNREACH', 'EHOSTDOWN', 'ENETDOWN']);
const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'ETIMEOUT']);

function classifyConnectError(code) {
  if (code === 'ECONNREFUSED') return 'refused';
  if (TIMEOUT_CODES.has(code)) return 'timeout';
  if (UNREACHABLE_CODES.has(code)) return 'unreachable';
  return 'error';
}

function codeOf(err) {
  const code = err && err.code != null ? String(err.code).trim() : '';
  return /^[A-Za-z0-9_]{1,32}$/.test(code) ? code.toUpperCase() : 'EUNKNOWN';
}

// TCP-connect probe: opens `count` connections to host:port, times each connect,
// and reports success/loss + RTT stats. No payload is sent — connect-and-close
// only. `connect` is injectable so tests need no real socket.
//
// `failure` + `errorCode` describe the LAST attempt that failed (both null when
// none did), so "port closed" is not reported as the same thing as "host gone".
async function tcpProbe(spec, { connect = net.connect, now = () => Date.now() } = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  const port = Number(spec && spec.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { ...fail('tcp', `${host}:${spec && spec.port}`, 'invalid host/port'), failure: null, errorCode: null };
  }
  const count = clampInt(spec.count, 3, 1, 20);
  const timeoutMs = clampInt(spec.timeoutMs, 5000, 100, 60000);
  const target = `${host}:${port}`;
  const rtts = [];
  let failure = null;
  let errorCode = null;
  for (let i = 0; i < count; i += 1) {
    const t0 = now();
    // eslint-disable-next-line no-await-in-loop
    const r = await connectOnce(host, port, timeoutMs, connect);
    if (r.ok) rtts.push(now() - t0);
    else { failure = r.failure; errorCode = r.errorCode; }
  }
  return summarize('tcp', target, rtts, count, { failure, errorCode });
}

// Resolves { ok, failure, errorCode } and never rejects.
function connectOnce(host, port, timeoutMs, connect) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result, sock) => {
      if (done) return;
      done = true;
      if (sock) { try { sock.destroy(); } catch { /* ignore */ } }
      resolve(result);
    };
    let sock;
    try {
      sock = connect({ host, port });
    } catch (err) {
      const errorCode = codeOf(err);
      resolve({ ok: false, failure: classifyConnectError(errorCode), errorCode });
      return;
    }
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish({ ok: true, failure: null, errorCode: null }, sock));
    // Our own deadline: nothing answered within timeoutMs.
    sock.once('timeout', () => finish({ ok: false, failure: 'timeout', errorCode: 'ETIMEDOUT' }, sock));
    sock.once('error', (err) => {
      const errorCode = codeOf(err);
      finish({ ok: false, failure: classifyConnectError(errorCode), errorCode }, sock);
    });
  });
}

module.exports = { tcpProbe, classifyConnectError };
