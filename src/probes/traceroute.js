'use strict';

const { execFile } = require('child_process');
const { round, safeHost } = require('./stats');
const { findAddress, resolveFamily, tracerouteCommands } = require('./ipFamily');

// Path probe via the system `traceroute` (Linux/macOS) / `tracert` (Windows).
// MTR-style: sends several probes per hop (`-q queries`) so every hop carries not
// just latency but *loss* and *jitter* — the per-hop metrics the server overlays
// on its path-visualisation graph. Returns hops:
//   [{ hop, ip, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs }]
//
// IPv6 is traced by the same code: which binary and flags to use lives in
// [`ipFamily`](./ipFamily.js), and a literal IPv6 target selects it on its own,
// so `traceroute({ host: '2001:db8::1' })` needs no extra parameter.
//
// `exec`/`platform` are injectable for tests.
async function traceroute(spec, { exec = execFile, platform = process.platform } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return { type: 'traceroute', target: rawHost, ok: false, error: 'invalid host', hops: [] };
  const maxHops = Math.max(1, Math.min(40, Number.parseInt(spec.maxHops, 10) || 20));
  // Windows tracert always sends 3 probes/hop and has no "queries" flag; on
  // Linux/macOS the operator can pick how many (default 3, the MTR-ish sweet spot).
  const queries = platform === 'win32' ? 3 : Math.max(1, Math.min(10, Number.parseInt(spec.queries, 10) || 3));
  const family = resolveFamily(spec && (spec.ip_version ?? spec.ipVersion), host);
  const candidates = tracerouteCommands({ platform, family, host, maxHops, queries });

  const run = await runFirstAvailable(exec, candidates);
  const hops = parseTraceroute(run.stdout, queries);
  const base = { type: 'traceroute', target: host, ipVersion: family, queries };
  // Surface *why* a run came back empty so the server/dashboard can explain it
  // instead of drawing a blank path: a missing binary (ENOENT) is the common
  // case on minimal hosts/containers; `killed` means it ran but timed out.
  if (hops.length === 0 && run.err) {
    const reason = run.missing ? `${run.bin} not installed`
      : run.err.killed ? `${run.bin} timed out`
      : String(run.err.message || 'failed').split('\n')[0].slice(0, 120);
    return { ...base, ok: false, hopCount: 0, hops: [], error: reason };
  }
  return { ...base, ok: hops.length > 0, hopCount: hops.length, hops };
}

// Runs the candidates in order, stopping at the first that EXISTS. A missing
// binary (ENOENT) falls through to the next; every other outcome — including a
// non-zero exit, which traceroute returns routinely while still printing a
// usable report — belongs to the binary that ran.
//
// When none is installed the reason names the FIRST candidate, the one the
// server's auto-install offers.
async function runFirstAvailable(exec, candidates) {
  let last = null;
  for (const c of candidates) {
    // eslint-disable-next-line no-await-in-loop
    const run = await runOnce(exec, c);
    if (run.err && run.err.code === 'ENOENT') { last = run; continue; }
    return run;
  }
  return { ...last, bin: candidates[0].bin, missing: true };
}

function runOnce(exec, { bin, args }) {
  return new Promise((resolve) => {
    exec(bin, args, { timeout: 60000 }, (err, stdout) => {
      resolve({ bin, err: err || null, missing: false, stdout: String(stdout || '') });
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
// a timeout ("*"). The hop address is the first one on the line, which works for
// both layouts: Linux prints it before the times, Windows after them.
//
// Address extraction is [`findAddress`](./ipFamily.js), which reads IPv4 and
// IPv6 alike. It used to be an IPv4-only regex, and that one line was the reason
// an IPv6 trace came back as a list of anonymous hops — every one of them
// indistinguishable from a router that declines to answer.
function parseTraceroute(text, queries = 3) {
  const hops = [];
  for (const line of String(text).split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const rest = m[2];
    const ip = findAddress(rest);
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
