'use strict';

const { execFile } = require('child_process');
const { fail, round, safeHost } = require('./stats');

// ICMP ping probe via the system `ping`. Parses packet-loss% and the
// min/avg/max/mdev RTT summary (Linux/macOS and Windows formats). `exec` is
// injectable so tests parse canned output without spawning a process.
function pingProbe(spec, { exec = execFile, platform = process.platform } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return Promise.resolve(fail('ping', rawHost, 'invalid host'));
  const count = Math.max(1, Math.min(20, Number.parseInt(spec.count, 10) || 4));
  // `--` marks the end of options so a host can never be parsed as a flag; on
  // Windows `ping` has no such marker, but safeHost() has already rejected any
  // leading-`-` target, so option injection is closed on both paths.
  const args = platform === 'win32'
    ? ['-n', String(count), host]
    : ['-c', String(count), '-w', '10', '--', host];
  return new Promise((resolve) => {
    exec('ping', args, { timeout: 20000 }, (err, stdout) => {
      const parsed = parsePing(String(stdout || ''));
      if (!parsed) return resolve(fail('ping', host, err ? 'ping failed' : 'unparseable output'));
      const success = Math.round(count * (1 - parsed.lossPct / 100));
      resolve({
        type: 'ping', target: host, ok: parsed.lossPct < 100, attempts: count, success,
        rttMs: parsed.avg, minMs: parsed.min, maxMs: parsed.max, jitterMs: parsed.mdev, lossPct: parsed.lossPct,
      });
    });
  });
}

// Parses "X% packet loss" and "min/avg/max/mdev = a/b/c/d ms" (mdev optional).
function parsePing(text) {
  // Loss: Linux/macOS "0% packet loss" and Windows "(0% loss)".
  const loss = text.match(/([\d.]+)\s*%\s*(?:packet\s+)?loss/i);
  let min; let avg; let max; let mdev = null;
  // Linux/macOS: "min/avg/max/mdev = a/b/c/d ms" (mdev optional).
  const unix = text.match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)(?:\/([\d.]+))?\s*ms/);
  if (unix) {
    min = Number(unix[1]); avg = Number(unix[2]); max = Number(unix[3]);
    mdev = unix[4] !== undefined ? Number(unix[4]) : null;
  } else {
    // Windows: "Minimum = 10ms, Maximum = 12ms, Average = 11ms".
    const win = text.match(/Minimum\s*=\s*([\d.]+)ms[\s\S]*?Maximum\s*=\s*([\d.]+)ms[\s\S]*?Average\s*=\s*([\d.]+)ms/i);
    if (win) { min = Number(win[1]); max = Number(win[2]); avg = Number(win[3]); }
  }
  if (!loss && min === undefined) return null;
  return {
    lossPct: loss ? round(Number(loss[1])) : 0,
    min: min !== undefined ? round(min) : null,
    avg: avg !== undefined ? round(avg) : null,
    max: max !== undefined ? round(max) : null,
    mdev: mdev !== null ? round(mdev) : null,
  };
}

module.exports = { pingProbe, parsePing };
