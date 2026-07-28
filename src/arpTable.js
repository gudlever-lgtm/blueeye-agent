'use strict';

const { execFile } = require('child_process');

// Reads this host's ARP / neighbour table and reports the IP↔MAC pairings it
// holds, so the server can answer "where is this MAC" and "what holds this IP" —
// the entry point for a technician who was told an address, not a hostname.
//
// The agent already exposed this data via the read-only EVIDENCE path
// (evidenceCollector's `arp.table`), but only as raw text captured when an
// incident cluster opened. Reporting it on the normal capabilities cycle makes
// it continuous rather than incidental. The server ingests both and records
// which source a row came from.
//
// Privacy by design: METADATA ONLY — address pairings visible on the local
// segment, exactly what the host's own stack already knows. Never payload, never
// a user identity, never a process or command name.
//
// Source per platform:
//   - Linux  : /proc/net/arp (no subprocess at all), falling back to `ip neigh`
//              — the file covers IPv4 only, so `ip neigh` is also consulted for
//              IPv6 neighbours when available
//   - macOS  : `arp -an`
//   - Windows: `arp -a`
//
// Best-effort throughout: any failure yields [] and never throws. A missing
// `ip`/`arp` binary, a locked-down container with no /proc, or an unparseable
// output format must not cost the capabilities report.

const EXEC_TIMEOUT_MS = 4000;
// Upper bound on reported entries. A busy L3 switch can hold tens of thousands
// of neighbours; the server stores one row per (agent, ip), so an unbounded
// report would turn one capabilities POST into a very large write. Freshest
// first, so the cap drops the stale end.
const DEFAULT_CAP = 2000;

const MAC_RE = /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function isIpv4(s) {
  return IPV4_RE.test(s) && s.split('.').every((o) => Number(o) <= 255);
}
function isIpv6(s) {
  return s.includes(':') && /^[0-9a-f:]+$/i.test(s) && !MAC_RE.test(s);
}
function isIp(s) {
  return isIpv4(s) || isIpv6(s);
}

// Strips an IPv6 zone suffix (fe80::1%eth0) — the zone is the local interface,
// which is reported separately.
function stripZone(ip) {
  const i = String(ip).indexOf('%');
  return i === -1 ? String(ip) : String(ip).slice(0, i);
}

// Normalises any accepted MAC spelling to lowercase colon form, or null.
// The server normalises identically (src/identity/arpTable.js), so a spelling
// difference here can never split one device into two.
function normalizeMac(raw) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (MAC_RE.test(s)) return s.replace(/-/g, ':').toLowerCase();
  return null;
}

// Addresses that are never a host identity: incomplete, broadcast, multicast,
// IEEE-reserved. Dropped here so they are never sent, rather than sent and
// filtered server-side.
//
// NOTE: locally-administered unicast (aa:…, 02:42:… — VMs and containers) is
// KEPT. Those are real hosts, and most hosts are virtual.
function isUsableMac(mac) {
  if (!mac) return false;
  if (mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff') return false;
  const first = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 1) === 0; // group bit clear = unicast
}

// --- parsers ----------------------------------------------------------------
// Each returns [{ ip, mac, interface }]. Pure, so the exact byte-level formats
// are unit-testable without a host that happens to have the right tool.

// /proc/net/arp — IPv4 only. Flags 0x2 (ATF_COM) means the entry is complete.
function parseProcNetArp(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6 || !isIpv4(f[0])) continue;
    const flags = parseInt(f[2], 16);
    if (!Number.isFinite(flags) || !(flags & 0x2)) continue;
    const mac = normalizeMac(f[3]);
    if (!isUsableMac(mac)) continue;
    out.push({ ip: f[0], mac, interface: f[5] || null });
  }
  return out;
}

// `ip neigh show` — IPv4 + IPv6. An entry without lladdr, or in FAILED /
// INCOMPLETE state, is not a binding we can trust.
function parseIpNeigh(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 3) continue;
    const ip = stripZone(f[0]);
    if (!isIp(ip)) continue;
    if (/\b(FAILED|INCOMPLETE)\b/.test(line)) continue;
    const llIdx = f.indexOf('lladdr');
    const devIdx = f.indexOf('dev');
    if (llIdx === -1) continue;
    const mac = normalizeMac(f[llIdx + 1]);
    if (!isUsableMac(mac)) continue;
    out.push({ ip, mac, interface: devIdx === -1 ? null : f[devIdx + 1] || null });
  }
  return out;
}

// BSD/macOS `arp -an`:  ? (192.168.1.1) at 00:11:.. [ether] on en0
function parseArpDashAn(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/\(([^)]+)\)\s+at\s+(\S+)/i);
    if (!m) continue;
    const ip = stripZone(m[1]);
    if (!isIp(ip)) continue;
    const mac = normalizeMac(m[2]);
    if (!isUsableMac(mac)) continue; // also drops <incomplete>
    const on = line.match(/\son\s+(\S+)/i);
    out.push({ ip, mac, interface: on ? on[1] : null });
  }
  return out;
}

// Windows `arp -a` — the interface is an IP carried across from a header line.
function parseWindowsArp(text) {
  const out = [];
  let iface = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    const hdr = line.match(/^Interface:\s+(\S+)/i);
    if (hdr) { iface = hdr[1]; continue; }
    const f = line.split(/\s+/);
    if (f.length < 2 || !isIpv4(f[0])) continue;
    if (f[2] && !/^(dynamic|static)$/i.test(f[2])) continue;
    const mac = normalizeMac(f[1]);
    if (!isUsableMac(mac)) continue;
    out.push({ ip: f[0], mac, interface: iface });
  }
  return out;
}

// --- collection --------------------------------------------------------------

function run(execFileFn, cmd, args) {
  return new Promise((resolve) => {
    try {
      execFileFn(cmd, args, { timeout: EXEC_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
        resolve(err ? null : String(stdout || ''));
      });
    } catch { resolve(null); }
  });
}

function readFileSafe(readFileFn, path) {
  try { return readFileFn(path, 'utf8'); } catch { return null; }
}

// Deduplicates on ip (the server keys one row per (agent, ip)) keeping the
// FIRST occurrence, so the /proc/net/arp reading wins over the `ip neigh` one
// for an address both report — they agree in practice, and picking a stable
// winner keeps repeated reports idempotent.
function dedupeByIp(entries, cap) {
  const seen = new Map();
  for (const e of entries) {
    if (!seen.has(e.ip)) seen.set(e.ip, e);
  }
  return [...seen.values()].slice(0, cap);
}

// Collects this host's ARP/neighbour table. Injectable exec/readFile/platform
// for tests. Returns [] on any failure (best-effort).
async function collectArpTable({
  platform = process.platform,
  execFileFn = execFile,
  readFileFn = require('fs').readFileSync,
  cap = DEFAULT_CAP,
} = {}) {
  try {
    let entries = [];
    if (platform === 'win32') {
      entries = parseWindowsArp(await run(execFileFn, 'arp', ['-a']));
    } else if (platform === 'darwin') {
      entries = parseArpDashAn(await run(execFileFn, 'arp', ['-an']));
    } else {
      // Linux: read /proc directly (no subprocess) for IPv4, then ask `ip neigh`
      // for the IPv6 neighbours /proc/net/arp cannot express. Either source
      // missing just yields fewer entries.
      const proc = readFileSafe(readFileFn, '/proc/net/arp');
      if (proc) entries = entries.concat(parseProcNetArp(proc));
      const neigh = await run(execFileFn, 'ip', ['neigh', 'show']);
      if (neigh) entries = entries.concat(parseIpNeigh(neigh));
      // Neither worked (a container with no /proc and no iproute2) — try the
      // portable tool before giving up.
      if (!entries.length) entries = parseArpDashAn(await run(execFileFn, 'arp', ['-an']));
    }
    return dedupeByIp(entries, cap);
  } catch {
    return [];
  }
}

module.exports = {
  collectArpTable,
  parseProcNetArp,
  parseIpNeigh,
  parseArpDashAn,
  parseWindowsArp,
  normalizeMac,
  isUsableMac,
  dedupeByIp,
  DEFAULT_CAP,
};
