'use strict';

const { execFile } = require('child_process');
const { round } = require('./stats');

// Path probe via the system `traceroute` (Linux/macOS) / `tracert` (Windows).
// Returns hops [{ hop, ip, rttMs }]. `exec` is injectable for tests.
function traceroute(spec, { exec = execFile, platform = process.platform } = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  if (!host) return Promise.resolve({ type: 'traceroute', target: host, ok: false, error: 'invalid host', hops: [] });
  const maxHops = Math.max(1, Math.min(40, Number.parseInt(spec.maxHops, 10) || 20));
  const bin = platform === 'win32' ? 'tracert' : 'traceroute';
  const args = platform === 'win32'
    ? ['-d', '-h', String(maxHops), host]
    : ['-n', '-m', String(maxHops), '-q', '1', host];
  return new Promise((resolve) => {
    exec(bin, args, { timeout: 60000 }, (_err, stdout) => {
      const hops = parseTraceroute(String(stdout || ''));
      resolve({ type: 'traceroute', target: host, ok: hops.length > 0, hopCount: hops.length, hops });
    });
  });
}

// Parses lines like "  3  10.0.0.1  12.3 ms" (and "* * *" timeouts -> ip null).
function parseTraceroute(text) {
  const hops = [];
  for (const line of String(text).split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const ip = (m[2].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) || [])[1] || null;
    const rtt = (m[2].match(/([\d.]+)\s*ms/) || [])[1];
    hops.push({ hop: Number(m[1]), ip, rttMs: rtt ? round(Number(rtt)) : null });
  }
  return hops;
}

module.exports = { traceroute, parseTraceroute };
