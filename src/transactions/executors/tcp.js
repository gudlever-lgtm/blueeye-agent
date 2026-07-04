'use strict';

const net = require('net');
const { phaseForError } = require('../phase');

// TCP-connect test: measures time-to-connect to target:port. `connect` is
// injectable so tests exercise the logic without opening a socket.
function tcpExecutor(test, { connect = net.connect, now = () => Date.now() } = {}) {
  const cfg = test.config || {};
  const host = test.target;
  const port = Number(cfg.port);
  const timeout = Number.isInteger(cfg.timeout_ms) ? cfg.timeout_ms : 5000;
  const t0 = now();
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; try { socket.destroy(); } catch { /* ignore */ } resolve(v); };
    let socket;
    try {
      socket = connect({ host, port });
    } catch (err) {
      resolve({ status: 'error', latency_ms: now() - t0, detail: { phase: phaseForError(err), errno: err.code || 'ECONNECT' } });
      return;
    }
    socket.setTimeout(timeout);
    socket.once('connect', () => finish({ status: 'ok', latency_ms: now() - t0 }));
    socket.once('timeout', () => finish({ status: 'timeout', latency_ms: now() - t0, detail: { phase: 'timeout', errno: 'ETIMEDOUT' } }));
    socket.once('error', (err) => finish({
      status: err.code === 'ETIMEDOUT' ? 'timeout' : 'fail',
      latency_ms: now() - t0,
      detail: { phase: phaseForError(err), errno: err.code || 'ECONN' },
    }));
  });
}

module.exports = { tcpExecutor };
