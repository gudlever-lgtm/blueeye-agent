'use strict';

const fs = require('fs');
const net = require('net');

const PROBE_TYPES = new Set(['ping', 'tcp', 'dns', 'traceroute']);

// Parses operator-configured probe targets. Accepts an array (of strings or
// {type,host,port} objects) or a comma-separated string. Each entry is one of:
//   "1.1.1.1"            → ping 1.1.1.1
//   "ping:1.1.1.1"       → ping 1.1.1.1
//   "tcp:host:443"       → tcp host:443
//   "dns:example.com"    → dns example.com
//   "host:443"           → tcp host:443 (host + numeric port, no type)
// IPv6 literals are supported — their colons are address characters, not
// separators: "2606:4700::1111", "ping:2606:4700::1111", "[2606:4700::1111]",
// "tcp:[2606:4700::1111]:443" and "tcp:2606:4700::1111:443" (port read from
// the right when what precedes it is a valid IPv6 address).
// Invalid entries (e.g. a tcp target without a valid port) are dropped.
function parseConfiguredTargets(value) {
  if (Array.isArray(value)) return value.map(normalizeOne).filter(Boolean);
  if (typeof value !== 'string' || !value.trim()) return [];
  return value.split(',').map((s) => parseOneSpec(s.trim())).filter(Boolean);
}

function normalizeOne(item) {
  if (typeof item === 'string') return parseOneSpec(item.trim());
  if (!item || typeof item !== 'object') return null;
  return parseOneSpec(`${item.type || 'ping'}:${item.host || item.target || ''}${item.port ? `:${item.port}` : ''}`);
}

// "[v6]" or "[v6]:port" → { host, port } (port may be undefined); else null.
function splitBracketed(s) {
  const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (!m) return null;
  return { host: m[1], port: m[2] !== undefined ? Number(m[2]) : undefined };
}

function parseOneSpec(s) {
  if (!s) return null;
  // A bare IPv6 literal — its colons are address chars, not separators.
  if (net.isIPv6(s)) return { type: 'ping', host: s };
  const parts = s.split(':');
  let type = 'ping';
  let host;
  let port;
  const bare = splitBracketed(s);
  if (bare) {
    host = bare.host;
    if (bare.port !== undefined) { type = 'tcp'; port = bare.port; }
  } else if (PROBE_TYPES.has(parts[0].toLowerCase()) && parts.length >= 2) {
    type = parts[0].toLowerCase();
    const rest = s.slice(parts[0].length + 1);
    const br = splitBracketed(rest);
    const lastColon = rest.lastIndexOf(':');
    const tail = lastColon === -1 ? '' : rest.slice(lastColon + 1);
    const headIsV6 = /^\d+$/.test(tail) && net.isIPv6(rest.slice(0, lastColon));
    if (br) {
      host = br.host;
      port = br.port;
    } else if (type === 'tcp' && headIsV6) {
      // tcp needs a port, so the host:port reading wins — with '::'
      // compression "…::1111:443" can ALSO parse as one valid IPv6 address.
      host = rest.slice(0, lastColon); // e.g. "tcp:2606:4700::1111:443"
      port = Number(tail);
    } else if (net.isIPv6(rest)) {
      host = rest; // e.g. "ping:2606:4700::1111" (no port)
    } else if (headIsV6) {
      host = rest.slice(0, lastColon);
      port = Number(tail);
    } else {
      host = parts[1];
      if (parts[2] !== undefined) port = Number(parts[2]);
    }
  } else if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    type = 'tcp'; host = parts[0]; port = Number(parts[1]);
  } else {
    host = parts[0];
  }
  host = (host || '').trim();
  if (!host) return null;
  const spec = { type, host };
  if (type === 'tcp') {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    spec.port = port;
  } else if (Number.isInteger(port) && port >= 1 && port <= 65535) {
    spec.port = port;
  }
  return spec;
}

// Decodes the default-route gateway from the contents of /proc/net/route.
// The Gateway column is a little-endian hex IPv4 (e.g. 0100A8C0 → 192.168.0.1);
// the default route is the row whose Destination is 00000000.
function gatewayFromProcRoute(text) {
  for (const line of String(text || '').split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 3 || f[1] === 'Destination') continue;
    if (f[1] !== '00000000') continue;
    if (!/^[0-9a-fA-F]{8}$/.test(f[2]) || f[2] === '00000000') continue;
    return hexToIp(f[2]);
  }
  return null;
}

// The interface name of the default route from /proc/net/route — column 0 (Iface)
// of the row whose Destination (column 1) is 00000000. Used to pick which NIC
// hsflowd samples when none is configured (or the configured one doesn't exist).
function defaultRouteInterface(text) {
  for (const line of String(text || '').split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 2 || f[0] === 'Iface') continue;
    if (f[1] === '00000000') return f[0];
  }
  return null;
}

function hexToIp(hex) {
  const bytes = [hex.slice(0, 2), hex.slice(2, 4), hex.slice(4, 6), hex.slice(6, 8)];
  return bytes.reverse().map((b) => parseInt(b, 16)).join('.');
}

// Extracts the non-loopback nameservers from /etc/resolv.conf contents. The
// systemd-resolved stub (127.0.0.x) and ::1 are skipped — pinging the local stub
// says nothing about upstream reachability.
function nameserversFromResolv(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.trim().match(/^nameserver\s+(\S+)/i);
    if (!m) continue;
    const ip = m[1];
    if (/^127\./.test(ip) || ip === '::1') continue;
    if (!out.includes(ip)) out.push(ip);
  }
  return out;
}

// Resolves the set of probe specs the agent runs on its schedule: the default
// gateway + DNS servers (auto-discovered) plus any operator-configured targets,
// de-duplicated. Readers/platform are injectable for tests.
async function resolveProbeTargets({
  configured = [], gateway = true, dns = true, count = 3,
  readRoute = () => fs.promises.readFile('/proc/net/route', 'utf8'),
  readResolv = () => fs.promises.readFile('/etc/resolv.conf', 'utf8'),
  platform = process.platform,
} = {}) {
  const specs = [];
  if (gateway && platform === 'linux') {
    try { const gw = gatewayFromProcRoute(await readRoute()); if (gw) specs.push({ type: 'ping', host: gw, count, role: 'gateway' }); } catch { /* no route info */ }
  }
  if (dns) {
    try { for (const ns of nameserversFromResolv(await readResolv())) specs.push({ type: 'ping', host: ns, count, role: 'dns' }); } catch { /* no resolv.conf */ }
  }
  for (const c of configured) specs.push({ count, ...c, role: c.role || 'configured' });

  const seen = new Set();
  const out = [];
  for (const s of specs) {
    const k = `${s.type}|${s.host}|${s.port || ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

module.exports = { parseConfiguredTargets, gatewayFromProcRoute, defaultRouteInterface, nameserversFromResolv, resolveProbeTargets };
