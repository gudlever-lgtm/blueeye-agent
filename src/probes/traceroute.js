'use strict';

const { execFile } = require('child_process');
const { round, safeHost } = require('./stats');

// Path probe via the system `traceroute` (Linux/macOS) / `tracert` (Windows).
// MTR-style: sends several probes per hop (`-q queries`) so every hop carries not
// just latency but *loss* and *jitter* — the per-hop metrics the server overlays
// on its path-visualisation graph. Returns hops:
//   [{ hop, ip, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs }]
// `exec`/`platform` are injectable for tests.
function traceroute(spec, { exec = execFile, platform = process.platform } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return Promise.resolve({ type: 'traceroute', target: rawHost, ok: false, error: 'invalid host', hops: [] });
  const maxHops = Math.max(1, Math.min(40, Number.parseInt(spec.maxHops, 10) || 20));
  // Windows tracert always sends 3 probes/hop and has no "queries" flag; on
  // Linux/macOS the operator can pick how many (default 3, the MTR-ish sweet spot).
  const queries = platform === 'win32' ? 3 : Math.max(1, Math.min(10, Number.parseInt(spec.queries, 10) || 3));
  const bin = platform === 'win32' ? 'tracert' : 'traceroute';
  // `--` ends option parsing so the host can never be read as a flag (Unix);
  // Windows `tracert` has no such marker but safeHost() already rejected any
  // leading-`-` target above.
  const args = platform === 'win32'
    ? ['-d', '-h', String(maxHops), host]
    : ['-n', '-m', String(maxHops), '-q', String(queries), '-w', '2', '--', host];
  return new Promise((resolve) => {
    exec(bin, args, { timeout: 60000 }, (err, stdout) => {
      const hops = parseTraceroute(String(stdout || ''), queries);
      // Surface *why* a run came back empty so the server/dashboard can explain it
      // instead of drawing a blank path: a missing binary (ENOENT) is the common
      // case on minimal hosts/containers; `killed` means it ran but timed out.
      if (hops.length === 0 && err) {
        const reason = err.code === 'ENOENT' ? `${bin} not installed`
          : err.killed ? `${bin} timed out`
          : String(err.message || 'failed').split('\n')[0].slice(0, 120);
        resolve({ type: 'traceroute', target: host, ok: false, hopCount: 0, queries, hops: [], error: reason });
        return;
      }
      resolve({ type: 'traceroute', target: host, ok: hops.length > 0, hopCount: hops.length, queries, hops });
    });
  });
}

// Aggregates the RTT samples + timeouts seen for one hop into a normalized hop
// record. loss% comes from the probes that didn't answer; jitter = mean absolute
// difference of consecutive RTT samples (RFC3550-style inter-packet variation).
function hopStats(hop, ip, samples, sent) {
  const recv = Math.min(samples.length, sent);
  const lossPct = sent > 0 ? round(((sent - recv) / sent) * 100) : 0;
  let rttMs = null;
  let minMs = null;
  let maxMs = null;
  let jitterMs = null;
  if (samples.length) {
    rttMs = round(samples.reduce((s, v) => s + v, 0) / samples.length);
    minMs = round(Math.min(...samples));
    maxMs = round(Math.max(...samples));
    let jsum = 0;
    for (let i = 1; i < samples.length; i += 1) jsum += Math.abs(samples[i] - samples[i - 1]);
    jitterMs = samples.length > 1 ? round(jsum / (samples.length - 1)) : 0;
  }
  return { hop, ip, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs };
}

// Parses a traceroute/tracert report into per-hop stats. Each hop line carries up
// to `queries` probes; a probe is either an RTT ("12.3 ms" / Windows "<1 ms") or
// a timeout ("*"). The hop IP is the first address on the line, which works for
// both layouts: Linux prints the IP before the times, Windows after them. With
// `-n`/`-d` no DNS names appear, so the IP regex is unambiguous.
function parseTraceroute(text, queries = 3) {
  const hops = [];
  for (const line of String(text).split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const rest = m[2];
    const ip = (rest.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) || [])[1] || null;
    const samples = [];
    const re = /(<\s*1|\d+(?:\.\d+)?)\s*ms/gi;
    let mm;
    while ((mm = re.exec(rest)) !== null) {
      const tok = mm[1].replace(/\s+/g, '');
      samples.push(tok[0] === '<' ? 0.5 : Number(tok));
    }
    hops.push(hopStats(Number(m[1]), ip, samples, queries));
  }
  return hops;
}

module.exports = { traceroute, parseTraceroute };
