'use strict';

const { execFile } = require('child_process');
const { round, safeHost } = require('./stats');
const { findAddress, findAllAddresses, resolveFamily, tracerouteCommands, TRACE_WAIT_MS } = require('./ipFamily');
const { nameHops } = require('./hopNames');

// Path probe via the system `traceroute` (Linux/macOS) / `tracert` (Windows).
// MTR-style: sends several probes per hop (`-q queries`) so every hop carries not
// just latency but *loss* and *jitter* — the per-hop metrics the server overlays
// on its path-visualisation graph. Returns hops:
//   [{ hop, ip, ips, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs }]
// `ip` is the first router that answered (the historical field); `ips` is
// every DISTINCT router that answered on that hop, in order — more than one
// means ECMP / load-balanced paths, which a single `ip` silently hid.
// `hostname` (only on public hops that have one) is the router's PTR name,
// looked up after the trace — see [`hopNames`](./hopNames.js). The server reads
// the city out of it to place the hop on the map.
//
// IPv6 is traced by the same code: which binary and flags to use lives in
// [`ipFamily`](./ipFamily.js), and a literal IPv6 target selects it on its own,
// so `traceroute({ host: '2001:db8::1' })` needs no extra parameter.
//
// `onHop(hop)` (optional) is called for every hop the moment the binary prints
// its line, so the server can draw the path while the trace is still running.
// The returned result is unchanged and stays the record.
//
// `exec`/`platform`/`reverse` are injectable for tests (`reverse: null` skips
// the name lookups).
async function traceroute(spec, { exec = execFile, platform = process.platform, onHop = null, reverse } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return { type: 'traceroute', target: rawHost, ok: false, error: 'invalid host', hops: [] };
  const maxHops = Math.max(1, Math.min(40, Number.parseInt(spec.maxHops, 10) || 20));
  // Windows tracert always sends 3 probes/hop and has no "queries" flag; on
  // Linux/macOS the operator can pick how many (default 3, the MTR-ish sweet spot).
  const queries = platform === 'win32' ? 3 : Math.max(1, Math.min(10, Number.parseInt(spec.queries, 10) || 3));
  const family = resolveFamily(spec && (spec.ip_version ?? spec.ipVersion), host);
  const candidates = tracerouteCommands({ platform, family, host, maxHops, queries });

  // THE RUN GETS AS LONG AS IT CAN HONESTLY NEED. A flat 60s killed traces that
  // were working: every silent hop costs queries x TRACE_WAIT_MS, so 20 hops
  // with a few black holes is well past a minute, and a killed run produces no
  // output — reported as "no hops", which reads as a missing tool rather than
  // an impatient timeout. Derived from the same numbers the command is built
  // with, plus headroom for DNS and process start, and capped so a probe can
  // never hold the runtime for an unbounded time.
  const budgetMs = Math.min(180000, maxHops * queries * TRACE_WAIT_MS + 15000);
  const run = await runFirstAvailable(exec, candidates, budgetMs, onHop, queries);
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
  await nameHops(hops, reverse === undefined ? {} : { reverse });
  return { ...base, ok: hops.length > 0, hopCount: hops.length, hops };
}

// Runs the candidates in order, stopping at the first that EXISTS. A missing
// binary (ENOENT) falls through to the next; every other outcome — including a
// non-zero exit, which traceroute returns routinely while still printing a
// usable report — belongs to the binary that ran.
//
// When none is installed the reason names the FIRST candidate, the one the
// server's auto-install offers.
async function runFirstAvailable(exec, candidates, timeoutMs, onHop = null, queries = 3) {
  let last = null;
  for (const c of candidates) {
    // eslint-disable-next-line no-await-in-loop
    const run = await runOnce(exec, c, timeoutMs, onHop, queries);
    if (run.err && run.err.code === 'ENOENT') { last = run; continue; }
    return run;
  }
  return { ...last, bin: candidates[0].bin, missing: true };
}

function runOnce(exec, { bin, args }, timeoutMs = 60000, onHop = null, queries = 3) {
  return new Promise((resolve) => {
    const child = exec(bin, args, { timeout: timeoutMs }, (err, stdout) => {
      resolve({ bin, err: err || null, missing: false, stdout: String(stdout || '') });
    });
    streamHops(child, queries, onHop);
  });
}

// Calls onHop(hop) for each complete hop line as the child prints it. execFile
// still buffers the whole output for its callback, so this only listens in; a
// fake exec without a stdout stream simply streams nothing. A listener that
// throws must not take the trace down with it.
function streamHops(child, queries, onHop) {
  if (typeof onHop !== 'function' || !child || !child.stdout || typeof child.stdout.on !== 'function') return;
  let buf = '';
  child.stdout.on('data', (chunk) => {
    buf += String(chunk);
    const lines = buf.split(/\r\n|\r|\n/);
    buf = lines.pop();
    for (const line of lines) {
      const hop = parseTraceroute(line, queries)[0];
      if (!hop) continue;
      try { onHop(hop); } catch { /* the live view is a courtesy */ }
    }
  });
}

// Aggregates the RTT samples + timeouts seen for one hop into a normalized hop
// record. loss% comes from the probes that didn't answer; jitter = mean absolute
// difference of consecutive RTT samples (RFC3550-style inter-packet variation).
function hopStats(hop, ip, samples, sent, ips = ip ? [ip] : []) {
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
  return { hop, ip, ips, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs };
}

// Parses a traceroute/tracert report into per-hop stats. Each hop line carries up
// to `queries` probes; a probe is either an RTT ("12.3 ms" / Windows "<1 ms") or
// a timeout ("*"). The hop address is the first one on the line, which works for
// both layouts: Linux prints it before the times, Windows after them.
//
// A hop line can name SEVERAL routers: with equal-cost multipath each probe of
// the same TTL may take a different path, and Linux traceroute prints every
// new address inline (` 2  10.1.0.1  1.2 ms 10.2.0.1  1.5 ms  10.1.0.1  1.3 ms`).
// `ip` stays the first (older servers read only that); `ips` lists each
// distinct one, in the order they answered.
//
// Address extraction is [`findAddress`](./ipFamily.js), which reads IPv4 and
// IPv6 alike. It used to be an IPv4-only regex, and that one line was the reason
// an IPv6 trace came back as a list of anonymous hops — every one of them
// indistinguishable from a router that declines to answer.
function parseTraceroute(text, queries = 3) {
  const hops = [];
  // SPLIT ON EITHER LINE ENDING. This is why a Windows agent reported "no hops"
  // from a tracert that worked: splitting on \n alone leaves a trailing \r on
  // every line but the last, and in JavaScript `.` does not match \r — so
  // `(.*)$` could not reach the end of the string and the line matched nothing.
  // Every hop was dropped except the one before "Trace complete.", which has no
  // \r of its own. Zero hops then reads as a missing traceroute binary, so the
  // dashboard told operators to install a tool that was already there.
  //
  // All three endings, not just CRLF: a lone \r breaks the match the same way,
  // and the cost of handling it is one alternation.
  for (const line of String(text).split(/\r\n|\r|\n/)) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const rest = m[2];
    const ip = findAddress(rest);
    const ips = findAllAddresses(rest);
    // findAddress has a glued-IPv4 fallback the token scan does not; the
    // headline address is always in the list, and always first.
    if (ip && !ips.includes(ip)) ips.unshift(ip);
    const samples = [];
    const re = /(<\s*1|\d+(?:\.\d+)?)\s*ms/gi;
    let mm;
    while ((mm = re.exec(rest)) !== null) {
      const tok = mm[1].replace(/\s+/g, '');
      samples.push(tok[0] === '<' ? 0.5 : Number(tok));
    }
    hops.push(hopStats(Number(m[1]), ip, samples, queries, ips));
  }
  return hops;
}

module.exports = { traceroute, parseTraceroute, streamHops };
