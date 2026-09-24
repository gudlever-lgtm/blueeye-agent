'use strict';

const { spawn: nodeSpawn } = require('child_process');
const dns = require('dns');
const fs = require('fs');
const { createPcapParser } = require('./pcapStream');
const { decodeFrame } = require('./decode');
const { targetsForTest, buildFilter, tcpdumpArgs } = require('./filter');
const { defaultRouteInterface, nameserversFromResolv } = require('../probes/targets');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Header capture, scoped to the traffic a transaction test generates itself.
//
// WHAT THIS IS FOR. The phase timings (transactions/phases.js) say WHERE a step
// spent its time. They cannot say why: a handshake that took 900 ms looks the
// same whether the SYN was retransmitted three times or the server was simply
// slow to accept. Retransmissions, duplicate ACKs, resets, zero windows and MSS
// mismatches are only visible on the wire, and those five things are the whole
// reason this module exists.
//
// THE CAPS ARE ENFORCED HERE, NOT ONLY IN THE SERVER. The same rule the burst
// runner follows (src/burst.js): the thing that observes traffic must not depend
// on the thing that asked having asked correctly.
//
//   snaplen   96 bytes, FIXED and not a parameter. Enough for Ethernet + IPv6 +
//             a TCP header with options; not enough to be a payload capture.
//   seconds   30 at the outside, and normally the test's own timeout + 2 s.
//   packets   2000, capped in tcpdump (-c) as well as in the ring here, so the
//             ceiling holds even if this process stops reading.
//   filter    derived from the test, never typed (see filter.js). No filter, no
//             capture — there is no unfiltered path.
//   scope     one capture per agent at a time, and only for the duration of the
//             run it belongs to.
//
// ON DISK: nothing. tcpdump writes its pcap stream to a pipe, each frame is
// decoded into a header record and the buffer is dropped. There is no file to
// delete afterwards because none is written.

const SNAPLEN = 96;
const MAX_SECONDS = 30;
const MAX_PACKETS = 2000;
const READY_TIMEOUT_MS = 3000;
const STOP_GRACE_MS = 1000;

// tcpdump names its own failure modes clearly enough to tell a missing binary
// from a missing privilege — and those need different answers from the operator.
const PERMISSION_RE = /permission denied|you don't have permission|operation not permitted|no permission/i;
const NO_DEVICE_RE = /no such device|SIOCETHTOOL|bogus devname|that device|not found/i;

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

// Is header capture possible on this host at all? Reported in capabilities so a
// dashboard can grey the option out WITH A REASON, rather than letting an
// operator ask for something that will always come back refused.
function detectCaptureSupport({ spawn = nodeSpawn, platform = process.platform } = {}) {
  return new Promise((resolve) => {
    if (platform !== 'linux') {
      resolve({ available: false, reason: `header capture is Linux-only (this host is ${platform})` });
      return;
    }
    let child;
    try {
      // -D lists the devices libpcap can open. It needs the same privilege a
      // capture does, so a host that can list can capture — which is exactly
      // the question, and it sends no packets to ask it.
      child = spawn('tcpdump', ['-D'], { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      resolve({ available: false, reason: `tcpdump could not be started (${(err && err.code) || 'spawn failed'})` });
      return;
    }
    let out = '';
    let err = '';
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve(v); };
    // NOT unref'd: this timer is awaited, and an unref'd timer does not keep
    // the event loop alive — the await would then hang until something else
    // happened to tick it.
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } done({ available: false, reason: 'tcpdump did not respond' }); }, READY_TIMEOUT_MS);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); done({ available: false, reason: e && e.code === 'ENOENT' ? 'tcpdump is not installed' : `tcpdump could not be started (${(e && e.code) || 'error'})` }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && /\d+\./.test(out)) { done({ available: true, reason: null }); return; }
      if (PERMISSION_RE.test(err)) { done({ available: false, reason: 'no CAP_NET_RAW (the agent may not open a capture device)' }); return; }
      done({ available: false, reason: `tcpdump exited ${code}${err ? `: ${err.trim().split('\n')[0].slice(0, 120)}` : ''}` });
    });
  });
}

function createCaptureRunner({
  spawn = nodeSpawn,
  logger = silentLogger,
  now = () => Date.now(),
  lookup = dns.lookup,
  readFile = (p) => fs.promises.readFile(p, 'utf8'),
  readProcNetRoute = () => fs.promises.readFile('/proc/net/route', 'utf8'),
  platform = process.platform,
} = {}) {
  // ONE AT A TIME, for the same reason a burst is: two tcpdumps on one NIC are
  // two copies of the load, and their records interleave into one unreadable
  // series.
  let active = null;

  function isRunning() { return active !== null; }

  // The host's configured resolvers, for a dns test — the traffic goes to them,
  // not to the name being resolved. Best-effort: no resolv.conf means no dns
  // capture, which is reported rather than replaced with something wider.
  async function resolvers() {
    try {
      const fromFile = nameserversFromResolv(await readFile('/etc/resolv.conf'));
      if (fromFile.length) return fromFile;
    } catch { /* fall through */ }
    try { return dns.getServers().filter((s) => !/^127\./.test(s) && s !== '::1'); } catch { return []; }
  }

  // Resolves each target name to an address ONCE, before the capture starts, so
  // the filter holds an IP literal. A name resolved again at connect time could
  // answer differently, and a filter built on the first answer would then be
  // capturing a host the test is not talking to.
  function resolveOne(host) {
    return new Promise((resolve) => {
      lookup(host, { family: 0 }, (err, address) => resolve(err ? null : address));
    });
  }

  async function pickInterface(explicit) {
    if (explicit && /^[A-Za-z0-9._:-]{1,32}$/.test(String(explicit))) return String(explicit);
    try {
      const iface = defaultRouteInterface(await readProcNetRoute());
      if (iface) return iface;
    } catch { /* fall through */ }
    // `any` is a real libpcap device on Linux and produces cooked frames, which
    // the decoder handles. It is the honest fallback when the default route
    // cannot be read.
    return 'any';
  }

  // Starts a capture for `test` and resolves once tcpdump is actually listening
  // — not once it has been spawned. The difference matters: returning early
  // means the test's SYN is sent before the capture is live, and the one packet
  // that identifies the fault is the one that goes missing.
  //
  // Resolves { ok: true, session } or { ok: false, reason }. Never throws: a
  // capture is an extra, and a test must run whether or not it could start.
  async function start(test, { iface: wantedIface = null, seconds = 15, maxPackets = MAX_PACKETS } = {}) {
    if (platform !== 'linux') return { ok: false, reason: `header capture is Linux-only (this host is ${platform})` };
    if (active) return { ok: false, reason: 'a capture is already running on this agent' };

    const names = targetsForTest(test, { resolvers: await resolvers() });
    if (!names.length) return { ok: false, reason: 'no capture targets could be derived from this test' };

    const resolved = [];
    for (const t of names) {
      // eslint-disable-next-line no-await-in-loop
      const ip = await resolveOne(t.host);
      if (ip) resolved.push({ ip, port: t.port, proto: t.proto });
    }
    if (!resolved.length) return { ok: false, reason: 'none of this test\'s targets could be resolved to an address' };

    const built = buildFilter(resolved);
    if (built.error) return { ok: false, reason: built.error };

    const cap = clampInt(maxPackets, MAX_PACKETS, 1, MAX_PACKETS);
    const limitSec = clampInt(seconds, 15, 1, MAX_SECONDS);
    const iface = await pickInterface(wantedIface);
    const args = tcpdumpArgs({ iface, expression: built.expression, snaplen: SNAPLEN, maxPackets: cap });

    let child;
    try {
      child = spawn('tcpdump', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      return { ok: false, reason: `tcpdump could not be started (${(err && err.code) || 'spawn failed'})` };
    }

    const parser = createPcapParser();
    const packets = [];
    const startedAt = now();
    let dropped = 0;      // over the ring cap — the capture saw more than it kept
    let undecodable = 0;  // matched the filter but was not IPv4/IPv6
    let stderrText = '';
    let exited = false;
    let exitReason = null;

    const session = {
      iface, filter: built.expression, targets: built.targets, startedAt, snaplen: SNAPLEN,
    };

    child.stdout.on('data', (chunk) => {
      let frames;
      try { frames = parser.push(chunk); } catch { return; }
      for (const f of frames) {
        if (packets.length >= cap) { dropped += 1; continue; }
        const rec = decodeFrame(f.frame, { linkType: parser.linkType(), tsMs: f.tsMs, wireLen: f.wireLen });
        if (rec) packets.push(rec); else undecodable += 1;
      }
    });
    child.stderr.on('data', (d) => { if (stderrText.length < 4096) stderrText += d; });
    child.on('error', (err) => { exited = true; exitReason = (err && err.code) || 'error'; });
    child.on('close', (code) => { exited = true; if (exitReason === null) exitReason = `exit ${code}`; });

    // Ready = the pcap global header has arrived on stdout. libpcap writes it
    // the moment the device is open, so this is the same signal across every
    // tcpdump version — unlike the "listening on …" line, whose wording moves.
    const ready = await new Promise((resolve) => {
      const deadline = now() + READY_TIMEOUT_MS;
      // NOT unref'd, for the same reason as above: this poll is awaited, so it
      // has to be what keeps the loop alive until it answers. Only the run
      // deadline below is a backstop and may be unref'd.
      const tick = () => {
        if (parser.linkType() !== null) { resolve(true); return; }
        if (exited) { resolve(false); return; }
        if (now() >= deadline) { resolve(false); return; }
        setTimeout(tick, 25);
      };
      tick();
    });

    if (!ready) {
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
      const first = stderrText.trim().split('\n')[0] || '';
      if (PERMISSION_RE.test(stderrText)) return { ok: false, reason: 'no CAP_NET_RAW (the agent may not open a capture device)' };
      if (NO_DEVICE_RE.test(stderrText)) return { ok: false, reason: `interface ${iface} could not be opened` };
      if (/ENOENT/.test(String(exitReason))) return { ok: false, reason: 'tcpdump is not installed' };
      return { ok: false, reason: first ? `tcpdump did not start: ${first.slice(0, 160)}` : 'tcpdump did not start listening in time' };
    }

    // A capture that outlives its run is a capture nobody asked for. The
    // deadline is a backstop for a test that hangs past its own timeout.
    const deadline = setTimeout(() => { try { child.kill('SIGTERM'); } catch { /* ignore */ } }, limitSec * 1000);
    if (deadline.unref) deadline.unref();

    // Ends the capture. `keep` decides whether anything survives this function:
    // on a run that passed, the records are dropped here and nothing is stored
    // or sent anywhere. That is the whole point of capturing into memory.
    async function stop({ keep = false, observedPorts = [] } = {}) {
      clearTimeout(deadline);
      if (active === session) active = null;
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      await new Promise((resolve) => {
        if (exited) { resolve(); return; }
        // Awaited, so not unref'd (see above).
        const hard = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } resolve(); }, STOP_GRACE_MS);
        child.once('close', () => { clearTimeout(hard); resolve(); });
      });

      const durationMs = now() - startedAt;
      if (!keep) {
        packets.length = 0;
        return { kept: false, packets: [], durationMs };
      }

      // Second narrowing, in memory: the filter could only name the far end, so
      // it also matched any other conversation this host had with that address
      // and port during the window. The run itself reports which local ports it
      // used, and everything else is discarded here — before a single record
      // reaches a buffer that leaves this function.
      const ports = new Set((observedPorts || []).filter((p) => Number.isInteger(p) && p > 0));
      const kept = ports.size
        ? packets.filter((p) => p.proto !== 6 || ports.has(p.sport) || ports.has(p.dport))
        : packets.slice();
      const foreign = packets.length - kept.length;

      return {
        kept: true,
        packets: kept,
        durationMs,
        iface,
        filter: built.expression,
        snaplen: SNAPLEN,
        linkType: parser.linkType(),
        observed: packets.length,
        dropped,
        undecodable,
        // How many packets matched the far end but belonged to another local
        // conversation. Reported rather than silently removed: it is the honest
        // measure of how sharply the capture was scoped.
        foreign,
        truncated: dropped > 0,
      };
    }

    session.stop = stop;
    active = session;
    return { ok: true, session };
  }

  // Stops whatever is running without keeping it. Used on shutdown, and when a
  // run fails in a way that leaves the capture orphaned.
  async function cancel() {
    if (!active) return false;
    try { await active.stop({ keep: false }); } catch { /* best-effort */ }
    active = null;
    return true;
  }

  return { start, cancel, isRunning, SNAPLEN, MAX_SECONDS, MAX_PACKETS };
}

// The local ports a finished transaction result actually used, read out of the
// phase records. This is what narrows a capture to the run that asked for it.
function observedPortsOf(result) {
  const phases = result && Array.isArray(result.step_phases) ? result.step_phases : [];
  const out = [];
  for (const p of phases) {
    if (p && Number.isInteger(p.localPort) && p.localPort > 0 && !out.includes(p.localPort)) out.push(p.localPort);
  }
  return out;
}

module.exports = { createCaptureRunner, detectCaptureSupport, observedPortsOf, SNAPLEN, MAX_SECONDS, MAX_PACKETS };
