'use strict';

const { execFile } = require('child_process');

// Reads this host's ESTABLISHED TCP connection table and folds it into directed
// service-dependency edges from THIS host's perspective, so a host that runs no
// flow exporter (proc/snmp source, no NetFlow/sFlow) still contributes to the
// server's service dependency graph.
//
// Privacy by design: METADATA ONLY — endpoint IPs + ports, never payload, never
// process/command. TCP only. Best-effort: any failure yields [] and never
// throws (a missing `ss`/`netstat` must not break capability reporting).
//
// Source per platform:
//   - Linux : `ss -Htan state established` (fallback `netstat -tn`)
//   - macOS : `netstat -anp tcp`
//   - Windows: PowerShell `Get-NetTCPConnection -State Established` (JSON)
//
// Direction: the ephemeral (high-port) side is the client → source; the service
// side (the non-ephemeral / lower port) is the destination, and its port is the
// edge's dst_port — the same key the server aggregates flows by.

const DEFAULT_EPHEMERAL_MIN = 32768; // Linux ip_local_port_range low end
const DEFAULT_CAP = 500; // max edges reported (heaviest by connection count)
const EXEC_TIMEOUT_MS = 4000;

// addr:port / [v6]:port / v6-with-colons:port — split on the LAST colon, honour
// the bracketed IPv6 form. Returns { addr, port } or null.
function splitHostPortColon(token) {
  if (token == null) return null;
  const s = String(token).trim();
  const br = s.match(/^\[(.+)\]:(\d+)$/);
  if (br) return { addr: br[1], port: Number(br[2]) };
  const i = s.lastIndexOf(':');
  if (i <= 0 || i === s.length - 1) return null;
  const port = Number(s.slice(i + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { addr: s.slice(0, i), port };
}

// macOS netstat uses addr.port (last DOT before the port). Works for IPv4
// (10.0.0.1.22) and IPv6 (2001:db8::1.443).
function splitHostPortDot(token) {
  if (token == null) return null;
  const s = String(token).trim();
  const i = s.lastIndexOf('.');
  if (i <= 0 || i === s.length - 1) return null;
  const port = Number(s.slice(i + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { addr: s.slice(0, i), port };
}

// `ss -Htan state established`: State Recv-Q Send-Q Local Peer.
function parseSs(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 5) continue;
    const local = splitHostPortColon(t[3]);
    const peer = splitHostPortColon(t[4]);
    if (local && peer) out.push({ localIp: local.addr, localPort: local.port, remoteIp: peer.addr, remotePort: peer.port });
  }
  return out;
}

// `netstat -tn` (Linux): tcp Recv-Q Send-Q Local Foreign State.
function parseNetstatLinux(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 6 || !/^tcp/i.test(t[0]) || t[5] !== 'ESTABLISHED') continue;
    const local = splitHostPortColon(t[3]);
    const foreign = splitHostPortColon(t[4]);
    if (local && foreign) out.push({ localIp: local.addr, localPort: local.port, remoteIp: foreign.addr, remotePort: foreign.port });
  }
  return out;
}

// `netstat -anp tcp` (macOS): Proto Recv-Q Send-Q Local Foreign State (addr.port).
function parseNetstatMac(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 6 || !/^tcp/i.test(t[0]) || t[5] !== 'ESTABLISHED') continue;
    const local = splitHostPortDot(t[3]);
    const foreign = splitHostPortDot(t[4]);
    if (local && foreign) out.push({ localIp: local.addr, localPort: local.port, remoteIp: foreign.addr, remotePort: foreign.port });
  }
  return out;
}

// PowerShell `Get-NetTCPConnection ... | ConvertTo-Json` — an array, or a single
// object when there is exactly one connection.
function parseWindows(text) {
  let data;
  try { data = JSON.parse(String(text || '').trim() || 'null'); } catch { return []; }
  if (!data) return [];
  const list = Array.isArray(data) ? data : [data];
  const out = [];
  for (const r of list) {
    if (!r) continue;
    const localPort = Number(r.LocalPort);
    const remotePort = Number(r.RemotePort);
    if (!Number.isInteger(localPort) || !Number.isInteger(remotePort)) continue;
    out.push({ localIp: String(r.LocalAddress), localPort, remoteIp: String(r.RemoteAddress), remotePort });
  }
  return out;
}

function isLoopbackOrWildcard(ip) {
  if (!ip) return true;
  const s = String(ip);
  return s === '::1' || s === '::' || s === '0.0.0.0' || s === '*' || s.startsWith('127.');
}

// Orient one connection into a directed edge (src depends on dst:dstPort). The
// ephemeral side is the client (source); the service side is the destination.
function orientEdge(c, ephemeralMin) {
  const lEph = c.localPort >= ephemeralMin;
  const rEph = c.remotePort >= ephemeralMin;
  let srcIp; let dstIp; let dstPort;
  if (lEph && !rEph) { srcIp = c.localIp; dstIp = c.remoteIp; dstPort = c.remotePort; } // this host is the client
  else if (rEph && !lEph) { srcIp = c.remoteIp; dstIp = c.localIp; dstPort = c.localPort; } // this host is the server
  else if (c.localPort <= c.remotePort) { srcIp = c.remoteIp; dstIp = c.localIp; dstPort = c.localPort; } // lower port = service
  else { srcIp = c.localIp; dstIp = c.remoteIp; dstPort = c.remotePort; }
  return { srcIp, dstIp, dstPort };
}

// Fold a list of connections into deduped directed edges with a connection
// count, dropping loopback/wildcard and self-edges, capped to the heaviest N.
function aggregateEdges(conns, { ephemeralMin = DEFAULT_EPHEMERAL_MIN, cap = DEFAULT_CAP } = {}) {
  const byKey = new Map();
  for (const c of Array.isArray(conns) ? conns : []) {
    if (!c || !Number.isInteger(c.localPort) || !Number.isInteger(c.remotePort)) continue;
    if (isLoopbackOrWildcard(c.localIp) || isLoopbackOrWildcard(c.remoteIp)) continue;
    const e = orientEdge(c, ephemeralMin);
    if (!e.srcIp || !e.dstIp || e.srcIp === e.dstIp) continue;
    if (!Number.isInteger(e.dstPort) || e.dstPort <= 0) continue;
    const key = `${e.srcIp}|${e.dstIp}|${e.dstPort}`;
    const cur = byKey.get(key);
    if (cur) cur.connCount += 1;
    else byKey.set(key, { srcIp: e.srcIp, dstIp: e.dstIp, dstPort: e.dstPort, connCount: 1 });
  }
  return [...byKey.values()]
    .sort((a, b) => b.connCount - a.connCount || a.dstPort - b.dstPort)
    .slice(0, cap);
}

function run(execFileFn, cmd, args) {
  return new Promise((resolve) => {
    try {
      execFileFn(cmd, args, { timeout: EXEC_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
        resolve(err ? null : String(stdout || ''));
      });
    } catch { resolve(null); }
  });
}

// Collect + aggregate this host's established TCP connections. Injectable exec +
// platform for tests. Returns [] on any failure (best-effort).
async function collectConnections({ platform = process.platform, execFileFn = execFile, ephemeralMin = DEFAULT_EPHEMERAL_MIN, cap = DEFAULT_CAP } = {}) {
  try {
    let conns = [];
    if (platform === 'win32') {
      const out = await run(execFileFn, 'powershell.exe', ['-NoProfile', '-Command', 'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress']);
      conns = parseWindows(out);
    } else if (platform === 'darwin') {
      const out = await run(execFileFn, 'netstat', ['-anp', 'tcp']);
      conns = parseNetstatMac(out);
    } else {
      // Linux (and other *nix): prefer ss, fall back to netstat.
      const ssOut = await run(execFileFn, 'ss', ['-Htan', 'state', 'established']);
      conns = parseSs(ssOut);
      if (!conns.length) conns = parseNetstatLinux(await run(execFileFn, 'netstat', ['-tn']));
    }
    return aggregateEdges(conns, { ephemeralMin, cap });
  } catch {
    return [];
  }
}

module.exports = {
  collectConnections,
  aggregateEdges,
  orientEdge,
  parseSs,
  parseNetstatLinux,
  parseNetstatMac,
  parseWindows,
  splitHostPortColon,
  splitHostPortDot,
  DEFAULT_EPHEMERAL_MIN,
  DEFAULT_CAP,
};
