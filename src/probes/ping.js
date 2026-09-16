'use strict';

const { execFile } = require('child_process');
const { fail, round, safeHost, clampInt } = require('./stats');

// ICMP ping probe via the system `ping`. Parses packet-loss% and the
// min/avg/max/mdev RTT summary (Linux/macOS and Windows formats). `exec` is
// injectable so tests parse canned output without spawning a process.
//
// SIZE SWEEP (`spec.sizes`) — the probe that tells an MTU blackhole from a
// broken link. A path that carries 64-byte packets and drops 1472-byte ones is
// not "lossy": it has an MTU smaller than the sender thinks, and the ICMP
// "fragmentation needed" that would have said so is being filtered. So the
// probe can send several payload sizes in one run and report each one
// separately:
//
//   { type:'ping', target, ok, ...baseline metrics...,
//     df: true,
//     sizes: [ { bytes, sent, recv, lossPct, rttMs, minMs, maxMs, jitterMs,
//                mtuHint?, error? }, … ] }
//
// The TOP-LEVEL metrics always describe the SMALLEST size in the sweep. That is
// deliberate: they feed reachability — probe outages, fleet health, anomaly
// findings — and a 1472-byte DF ping that a tunnel drops must not read as "this
// host is down" on every screen in the product. The per-size detail is what the
// diagnosis reads; the headline stays the answer to "can I reach it at all".
//
// Without `sizes` the probe behaves exactly as it always has.

// How many sizes one sweep may carry. Each size is its own `ping` invocation,
// so this bounds the run, not just the payload.
const MAX_SIZES = 6;
// The largest payload we will ask for. 65500 is the practical ceiling of the
// system tools; anything above it is a typo, not a measurement.
const MAX_PAYLOAD = 65500;

// Builds the argv for one `ping` run. `--` marks the end of options so a host
// can never be parsed as a flag; on Windows `ping` has no such marker, but
// safeHost() has already rejected any leading-`-` target, so option injection is
// closed on both paths.
//
// Payload size and don't-fragment are spelled differently everywhere:
//   linux    -s <payload>   -M do
//   darwin   -s <payload>   -D
//   win32    -l <payload>   -f
//
// So is the deadline. Linux has `-w <seconds>` (whole run), macOS has
// `-t <seconds>`, and Windows' `-w` is a PER-REPLY timeout in milliseconds.
// They were previously all handed Linux's `-w 10`, which macOS `ping` rejects
// outright as an unknown option — a size sweep there would have come back
// unmeasured for every size. The deadline matters more now: a DF packet above
// the path MTU is dropped in silence, so every failing step of an MTU search
// costs exactly this long.
function buildPingArgs({ platform, count, host, size = null, df = false, deadlineSec = 10 }) {
  const deadline = Math.max(1, Math.min(60, Number.parseInt(deadlineSec, 10) || 10));
  if (platform === 'win32') {
    const args = ['-n', String(count), '-w', String(deadline * 1000)];
    if (size != null) args.push('-l', String(size));
    if (df) args.push('-f');
    args.push(host);
    return args;
  }
  const args = ['-c', String(count)];
  args.push(platform === 'darwin' ? '-t' : '-w', String(deadline));
  if (size != null) args.push('-s', String(size));
  if (df) {
    if (platform === 'darwin') args.push('-D');
    else args.push('-M', 'do');
  }
  args.push('--', host);
  return args;
}

// The next-hop MTU a router volunteered in an ICMP "fragmentation needed".
// Linux prints `Frag needed and DF set (mtu = 1400)`; when it appears, PMTUD is
// WORKING — the path is telling us its limit — which is the opposite of a
// blackhole and worth capturing as its own fact.
function parseMtuHint(text) {
  const m = String(text || '').match(/mtu\s*=\s*(\d+)/i);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
}

// Did the LOCAL stack refuse the packet before it ever left? A payload larger
// than this host's own interface MTU is a different finding from a path that
// drops it: nothing was measured, so reporting it as loss would be a lie.
function isLocalTooLong(text) {
  return /message too long|packet needs to be fragmented but df set|local error/i.test(String(text || ''));
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

// One `ping` invocation at one payload size. Resolves to a per-size record and
// NEVER rejects: an unparseable run is reported as 100% loss with the reason, so
// one bad size cannot take the sweep down with it.
function pingOnce({ host, count, size, df, exec, platform, deadlineSec = 10, timeoutMs = 20000 }) {
  const args = buildPingArgs({ platform, count, host, size, df, deadlineSec });
  return new Promise((resolve) => {
    exec('ping', args, { timeout: timeoutMs }, (err, stdout, stderr) => {
      const text = `${String(stdout || '')}\n${String(stderr || '')}`;
      const parsed = parsePing(text);
      const mtuHint = parseMtuHint(text);
      if (!parsed) {
        // No summary line at all. Either the local stack refused the payload, or
        // the binary is missing / the run was killed. Both are "not measured".
        const reason = isLocalTooLong(text) ? 'payload exceeds the local interface MTU'
          : err && err.code === 'ENOENT' ? 'ping not installed'
          : err && err.killed ? 'ping timed out'
          : err ? String(err.message || 'ping failed').split('\n')[0].slice(0, 120)
          : 'unparseable output';
        return resolve({
          measured: false,
          bytes: size, sent: count, recv: 0, lossPct: 100,
          rttMs: null, minMs: null, maxMs: null, jitterMs: null,
          mtuHint, error: reason,
        });
      }
      const recv = Math.round(count * (1 - parsed.lossPct / 100));
      return resolve({
        measured: true,
        bytes: size, sent: count, recv, lossPct: parsed.lossPct,
        rttMs: parsed.avg, minMs: parsed.min, maxMs: parsed.max, jitterMs: parsed.mdev,
        mtuHint, error: null,
      });
    });
  });
}

// Normalises spec.sizes: integers only, deduped, ascending, bounded. Returns
// null when no sweep was asked for (the ordinary single-ping path).
function normalizeSizes(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const seen = new Set();
  for (const v of raw) {
    const n = Number.parseInt(v, 10);
    if (!Number.isInteger(n) || n < 0 || n > MAX_PAYLOAD) continue;
    seen.add(n);
  }
  if (seen.size === 0) return null;
  return [...seen].sort((a, b) => a - b).slice(0, MAX_SIZES);
}

async function pingProbe(spec, { exec = execFile, platform = process.platform } = {}) {
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) return fail('ping', rawHost, 'invalid host');
  const count = clampInt(spec && spec.count, 4, 1, 20);
  const sizes = normalizeSizes(spec && spec.sizes);
  const df = (spec && spec.df) === true;

  if (!sizes) {
    const one = await pingOnce({ host, count, size: null, df, exec, platform });
    if (!one.measured) {
      // Nothing was measured at all — keep the historical shape of a hard failure.
      const res = fail('ping', host, one.error);
      if (df) res.df = true;
      if (one.mtuHint != null) res.mtuHint = one.mtuHint;
      return res;
    }
    const res = {
      type: 'ping', target: host, ok: one.lossPct < 100, attempts: count, success: one.recv,
      rttMs: one.rttMs, minMs: one.minMs, maxMs: one.maxMs, jitterMs: one.jitterMs, lossPct: one.lossPct,
    };
    if (df) res.df = true;
    if (one.mtuHint != null) res.mtuHint = one.mtuHint;
    return res;
  }

  // Sweep. Sequential on purpose: several concurrent pings to one target skew
  // each other's RTT, and the sizes are being compared against each other.
  const results = [];
  for (const size of sizes) {
    // eslint-disable-next-line no-await-in-loop
    results.push(await pingOnce({ host, count, size, df, exec, platform }));
  }
  const baseline = results[0]; // the smallest size — see the module note
  const hint = results.map((r) => r.mtuHint).find((v) => v != null);
  const res = {
    type: 'ping', target: host, ok: baseline.lossPct < 100, attempts: count, success: baseline.recv,
    rttMs: baseline.rttMs, minMs: baseline.minMs, maxMs: baseline.maxMs, jitterMs: baseline.jitterMs,
    lossPct: baseline.lossPct,
    df,
    sizes: results,
  };
  if (hint != null) res.mtuHint = hint;
  // A sweep where the smallest size did not come back measured nothing about
  // size at all; say why rather than let the caller read it as size-dependence.
  if (!baseline.measured) res.detail = baseline.error;
  return res;
}

module.exports = { pingProbe, pingOnce, parsePing, parseMtuHint, buildPingArgs, normalizeSizes, MAX_SIZES };
