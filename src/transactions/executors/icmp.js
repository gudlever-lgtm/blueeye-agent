'use strict';

const { execFile } = require('child_process');
const { parsePing } = require('../../probes/ping');
const { safeHost } = require('../../probes/stats');

// ICMP test: one system `ping` packet, parsed cross-platform (Linux/iputils,
// BSD/macOS, Windows) via the shared parsePing. `exec`/`platform` are injectable
// so tests parse canned output without spawning a process.
function icmpExecutor(test, { exec = execFile, platform = process.platform, now = () => Date.now() } = {}) {
  const cfg = test.config || {};
  // `test.target` is server-pushed transaction config; sanitize it exactly like
  // the standalone ping probe (probes/ping.js) so a target starting with '-'
  // (e.g. '-f') can never be parsed by `ping` as an option — argument injection
  // from a malicious/compromised server. Reject an unsafe target rather than run.
  const host = safeHost(test.target);
  const timeoutMs = Number.isInteger(cfg.timeout_ms) ? cfg.timeout_ms : 5000;
  const t0 = now();
  if (!host) {
    return Promise.resolve({ status: 'error', latency_ms: 0, detail: { phase: 'error', errno: 'INVALID_TARGET' } });
  }
  // 1 packet; per-platform deadline flags. Windows -w is ms; unix -W is seconds.
  // `--` marks end-of-options on unix so the host can never be read as a flag;
  // Windows ping has no `--`, but safeHost() has already rejected a leading '-'.
  const args = platform === 'win32'
    ? ['-n', '1', '-w', String(timeoutMs), host]
    : ['-c', '1', '-W', String(Math.max(1, Math.ceil(timeoutMs / 1000))), '--', host];
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
