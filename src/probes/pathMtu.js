'use strict';

const { execFile } = require('child_process');
const { round, safeHost, clampInt } = require('./stats');
const { pingOnce } = require('./ping');
const { traceroute } = require('./traceroute');

// Path MTU discovery — what the path will actually carry, and whether it says so.
//
// A TCP session that completes its handshake and then stalls the moment real
// data flows is almost never "packet loss". The handshake and the small command
// exchanges fit; the first full-size segment does not, some router on the way
// drops it, and the ICMP "fragmentation needed" that would have told the sender
// to send smaller is filtered by a firewall along the way. Nothing reports an
// error. The connection simply stops. That is a PMTUD blackhole, and it is
// invisible to every probe that only sends small packets.
//
// This probe sends don't-fragment packets and binary-searches for the largest
// one that survives, then says which of the two worlds it is in:
//
//   blackholeDetected: false — a router answered with "fragmentation needed
//     (mtu = N)". PMTUD is working. The path has a small MTU and says so, and
//     any host that listens to ICMP will cope on its own.
//   blackholeDetected: true — large packets vanish and nothing ever comes back
//     to explain it. This is the one that breaks applications, and the fix is a
//     firewall rule (allow ICMP type 3 code 4) or MSS clamping, not a smaller
//     MTU on the client.
//
// Result:
//   { type:'path_mtu', target, ok, pathMtu, blackholeDetected, recommendedMss,
//     mtuHint, mtuDropAtHop, low, high, overheadBytes, probes:[…], hops?:[…] }
//
// Every number is reported with the payload it came from (`probes`), because an
// MTU quoted without the packet that proved it is not evidence.

// What sits in front of the payload on the wire. An ICMP echo carries an 8-byte
// ICMP header inside an IP header — 20 bytes for IPv4, 40 for IPv6. A hostname
// could resolve to either; we cannot see which without resolving it ourselves,
// so a literal IPv6 target uses the v6 figure and everything else assumes IPv4.
// `overheadBytes` rides on the result so a reader can check the arithmetic
// rather than take the MTU on faith.
const IPV4_OVERHEAD = 28;
const IPV6_OVERHEAD = 48;

// The MTU the search starts from: 1472 payload = a 1500-byte Ethernet frame,
// which is what a client assumes until something tells it otherwise.
const DEFAULT_HIGH = 1472;
// The floor. 548 payload = 576 bytes, the smallest IPv4 datagram every host must
// accept. Below this the answer is not "small MTU", it is "broken path".
const DEFAULT_LOW = 548;
// A DF packet over the path MTU is dropped in silence, so a failing step costs
// the full deadline. Two seconds, and one packet per step: the search is a
// bisection, not a measurement of loss.
const STEP_DEADLINE_SEC = 2;
const STEP_TIMEOUT_MS = 6000;
// The search is over payload sizes, so it terminates in ~log2(high-low) steps.
// The cap is belt-and-braces against a bad low/high pair, not the real bound.
const MAX_STEPS = 16;
// Per-hop localisation is a second traceroute's worth of work on top, so it is
// opt-in and bounded.
const MAX_HOP_PROBES = 20;

const overheadFor = (host) => (host.includes(':') ? IPV6_OVERHEAD : IPV4_OVERHEAD);

// TCP's MSS is what is left of the MTU after the IP and TCP headers (20 each for
// IPv4, 40 + 20 for IPv6) — the number that goes on a `ip tcp adjust-mss` line.
function mssFor(pathMtu, overhead) {
  const headers = overhead === IPV6_OVERHEAD ? 60 : 40;
  const mss = pathMtu - headers;
  return mss > 0 ? mss : null;
}

// One don't-fragment step. `ok` means the packet came back whole; anything else
// (loss, a local refusal, a router's frag-needed) is a failure at this size.
async function step({ host, size, exec, platform, probes }) {
  const r = await pingOnce({
    host, count: 1, size, df: true, exec, platform,
    deadlineSec: STEP_DEADLINE_SEC, timeoutMs: STEP_TIMEOUT_MS,
  });
  const rec = {
    bytes: size,
    packetBytes: size + overheadFor(host),
    ok: r.measured && r.lossPct < 100,
    lossPct: r.lossPct,
    rttMs: r.rttMs,
    mtuHint: r.mtuHint,
    error: r.error,
  };
  probes.push(rec);
  return rec;
}

async function pathMtuProbe(spec, deps = {}) {
  const {
    exec = execFile,
    platform = process.platform,
    trace = traceroute,
  } = deps;
  const rawHost = String((spec && (spec.host || spec.target)) || '').trim();
  const host = safeHost(rawHost);
  if (!host) {
    return { type: 'path_mtu', target: rawHost, ok: false, error: 'invalid host', probes: [] };
  }
  const overheadBytes = overheadFor(host);
  const high = clampInt(spec && spec.high, DEFAULT_HIGH, 1, 65500);
  const low = Math.min(clampInt(spec && spec.low, DEFAULT_LOW, 0, 65500), high);
  const probes = [];

  const base = {
    type: 'path_mtu', target: host, low, high, overheadBytes,
    pathMtu: null, blackholeDetected: false, recommendedMss: null,
    mtuHint: null, mtuDropAtHop: null,
  };

  // Does the target answer at all? A DF packet at the floor that does not come
  // back means the path is down or ICMP is dropped end to end. Either way there
  // is no MTU to report, and reporting one anyway would be an invention.
  const floor = await step({ host, size: low, exec, platform, probes });
  if (!floor.ok) {
    return {
      ...base, ok: false, probes,
      error: floor.error || `no answer at ${low + overheadBytes} bytes — the path is down, or it filters ICMP echo entirely`,
    };
  }

  // The happy path: the full-size packet gets through, so nothing is clamping.
  const ceiling = await step({ host, size: high, exec, platform, probes });
  if (ceiling.ok) {
    const pathMtu = high + overheadBytes;
    return {
      ...base, ok: true, pathMtu, recommendedMss: mssFor(pathMtu, overheadBytes),
      probes,
      detail: `${pathMtu} bytes pass with DF set`,
    };
  }

  // Bisect. Invariant: `lo` passed, `hi` failed, and the answer is in between.
  let lo = low;
  let hi = high;
  for (let i = 0; i < MAX_STEPS && hi - lo > 1; i += 1) {
    const mid = Math.floor((lo + hi) / 2);
    // eslint-disable-next-line no-await-in-loop
    const r = await step({ host, size: mid, exec, platform, probes });
    if (r.ok) lo = mid; else hi = mid;
  }

  const pathMtu = lo + overheadBytes;
  // A router that volunteered its MTU is a router that is NOT blackholing. One
  // hint anywhere in the run is enough: it means the ICMP made it back to us.
  const mtuHint = probes.map((p) => p.mtuHint).find((v) => v != null) ?? null;
  const blackholeDetected = mtuHint == null;

  let mtuDropAtHop = null;
  let hops;
  if (spec && spec.perHop === true) {
    const located = await locateDrop({ host, failingSize: lo + 1, exec, platform, trace, spec });
    mtuDropAtHop = located.mtuDropAtHop;
    hops = located.hops;
  }

  const res = {
    ...base, ok: true, pathMtu, blackholeDetected,
    recommendedMss: mssFor(pathMtu, overheadBytes),
    mtuHint, mtuDropAtHop, probes,
    detail: blackholeDetected
      ? `${pathMtu} bytes is the largest that passes; larger packets are dropped without any ICMP reply (PMTUD blackhole)`
      : `${pathMtu} bytes is the largest that passes; a router reported mtu = ${mtuHint}`,
  };
  if (hops) res.hops = hops;
  return res;
}

// Which hop stops carrying the packet. Runs a traceroute, then asks each
// responding hop the same question twice: does it answer a small packet, and
// does it answer one just over the measured path MTU. Only a hop that answers
// the small one counts — a router that ignores ICMP echo altogether would
// otherwise look exactly like the one that is dropping oversized packets, and
// naming the wrong hop sends somebody to the wrong firewall.
async function locateDrop({ host, failingSize, exec, platform, trace, spec }) {
  let hopList = [];
  try {
    const tr = await trace({ host, maxHops: clampInt(spec && spec.maxHops, 20, 1, 40), queries: 1 }, { exec, platform });
    hopList = Array.isArray(tr && tr.hops) ? tr.hops : [];
  } catch {
    hopList = [];
  }
  const candidates = hopList.filter((h) => h && h.ip).slice(0, MAX_HOP_PROBES);
  const hops = [];
  let mtuDropAtHop = null;
  for (const h of candidates) {
    const ip = safeHost(h.ip);
    if (!ip) continue;
    // eslint-disable-next-line no-await-in-loop
    const small = await pingOnce({ host: ip, count: 1, size: 64, df: true, exec, platform, deadlineSec: STEP_DEADLINE_SEC, timeoutMs: STEP_TIMEOUT_MS });
    const respondsSmall = small.measured && small.lossPct < 100;
    let okAtLarge = null;
    if (respondsSmall) {
      // eslint-disable-next-line no-await-in-loop
      const large = await pingOnce({ host: ip, count: 1, size: failingSize, df: true, exec, platform, deadlineSec: STEP_DEADLINE_SEC, timeoutMs: STEP_TIMEOUT_MS });
      okAtLarge = large.measured && large.lossPct < 100;
      if (!okAtLarge && mtuDropAtHop == null) mtuDropAtHop = h.hop;
    }
    hops.push({ hop: h.hop, ip: h.ip, respondsSmall, okAtLarge, rttMs: round(small.rttMs) });
  }
  return { mtuDropAtHop, hops };
}

module.exports = { pathMtuProbe, locateDrop, mssFor, DEFAULT_HIGH, DEFAULT_LOW, IPV4_OVERHEAD, IPV6_OVERHEAD };
