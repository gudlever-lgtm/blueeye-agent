'use strict';

const net = require('net');
const { clampInt, summarize, fail } = require('./stats');

// TCP-connect probe: opens `count` connections to host:port, times each connect,
// and reports success/loss + RTT stats. No payload is sent — connect-and-close
// only. `connect` is injectable so tests need no real socket.
async function tcpProbe(spec, { connect = net.connect, now = () => Date.now() } = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  const port = Number(spec && spec.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('tcp', `${host}:${spec && spec.port}`, 'invalid host/port');
  }
  const count = clampInt(spec.count, 3, 1, 20);
  const timeoutMs = clampInt(spec.timeoutMs, 5000, 100, 60000);
  const target = `${host}:${port}`;
  const rtts = [];
  for (let i = 0; i < count; i += 1) {
    const t0 = now();
    // eslint-disable-next-line no-await-in-loop
    const ok = await connectOnce(host, port, timeoutMs, connect);
    if (ok) rtts.push(now() - t0);
  }
  return summarize('tcp', target, rtts, count);
}

function connectOnce(host, port, timeoutMs, connect) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok, sock) => {
      if (done) return;
      done = true;
      if (sock) { try { sock.destroy(); } catch { /* ignore */ } }
      resolve(ok);
    };
    let sock;
    try { sock = connect({ host, port }); } catch { resolve(false); return; }
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true, sock));
    sock.once('timeout', () => finish(false, sock));
    sock.once('error', () => finish(false, sock));
  });
}

module.exports = { tcpProbe };
