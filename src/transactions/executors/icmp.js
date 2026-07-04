'use strict';

const { execFile } = require('child_process');
const { parsePing } = require('../../probes/ping');

// ICMP test: one system `ping` packet, parsed cross-platform (Linux/iputils,
// BSD/macOS, Windows) via the shared parsePing. `exec`/`platform` are injectable
// so tests parse canned output without spawning a process.
function icmpExecutor(test, { exec = execFile, platform = process.platform, now = () => Date.now() } = {}) {
  const cfg = test.config || {};
  const host = test.target;
  const timeoutMs = Number.isInteger(cfg.timeout_ms) ? cfg.timeout_ms : 5000;
  // 1 packet; per-platform deadline flags. Windows -w is ms; unix -W is seconds.
  const args = platform === 'win32'
    ? ['-n', '1', '-w', String(timeoutMs), host]
    : ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), host];
  const t0 = now();
  return new Promise((resolve) => {
    exec('ping', args, { timeout: timeoutMs + 2000 }, (err, stdout) => {
      const parsed = parsePing(String(stdout || ''));
      if (!parsed) {
        if (err && err.killed) return resolve({ status: 'timeout', latency_ms: now() - t0, detail: { phase: 'timeout', errno: 'ETIMEDOUT' } });
        if (err && err.code === 'ENOENT') return resolve({ status: 'error', latency_ms: now() - t0, detail: { phase: 'error', errno: 'PING_MISSING' } });
        return resolve({ status: 'fail', latency_ms: now() - t0, detail: { phase: 'connect', errno: (err && err.code) || 'EPING' } });
      }
      if (parsed.lossPct >= 100) return resolve({ status: 'fail', latency_ms: now() - t0, detail: { phase: 'connect', errno: 'LOSS' } });
      return resolve({ status: 'ok', latency_ms: parsed.avg != null ? parsed.avg : (now() - t0) });
    });
  });
}

module.exports = { icmpExecutor };
