'use strict';

const dgram = require('dgram');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { defaultRouteInterface } = require('./targets');

// Active DHCP test: is there a DHCP server on this segment, and is there only
// ONE?
//
// The probe broadcasts a DHCPDISCOVER (RFC 2131 §4.4.1) and collects every
// DHCPOFFER that answers it until the timeout. It NEVER sends a DHCPREQUEST, so
// no lease is taken and no server commits an address to us: an offer is only a
// proposal, and a server that hears nothing further lets it lapse (RFC 2131
// §4.3.1 — the server "need not" reserve it). That is what makes it safe to run
// on a schedule against a production network, including a flat OT network with
// a small pool.
//
// Two faults, two answers:
//   - no offer at all  → the DHCP server (or the relay in front of it) is down;
//                        every device that reboots now comes up without an address.
//   - offers from more than one server identifier → a rogue or misconfigured
//                        DHCP server. On a flat OT segment that is a security
//                        event as much as an availability one: whoever answers
//                        first hands out the default gateway and the resolver.
//
// Split in two, like every other probe here: a PURE codec (buildDiscover,
// parseDhcpPacket, offerFromPacket — Buffers in, objects out, unit-tested on
// real-shaped packets) and a runner whose socket, interface table, clock and
// xid are all injectable, so the tests need neither root nor a network.
//
// Metadata only: what is reported is the server identifier, the offered
// address/lease/router/DNS/mask and the relay address — the fields an operator
// needs to find the server. Nothing else from the packet leaves the host.

const CLIENT_PORT = 68;
const SERVER_PORT = 67;
const BROADCAST = '255.255.255.255';
const MAGIC_COOKIE = Buffer.from([99, 130, 83, 99]);
// BOOTP's fixed header: op..file (RFC 951 / RFC 2131 §2), then the cookie.
const FIXED_LEN = 236;
const OPTIONS_OFFSET = FIXED_LEN + 4;
// Many relay agents and older servers drop a BOOTP message shorter than the
// original 300-byte BOOTP minimum (RFC 1542 §2.1), so the DISCOVER is padded.
const MIN_PACKET_LEN = 300;
const BOOTREQUEST = 1;
const BOOTREPLY = 2;
const HTYPE_ETHERNET = 1;
const FLAG_BROADCAST = 0x8000;

const MSG = { DISCOVER: 1, OFFER: 2, REQUEST: 3, DECLINE: 4, ACK: 5, NAK: 6, RELEASE: 7, INFORM: 8 };
const OPT = {
  PAD: 0, SUBNET_MASK: 1, ROUTER: 3, DNS: 6, DOMAIN_NAME: 15, LEASE_TIME: 51,
  OVERLOAD: 52, MESSAGE_TYPE: 53, SERVER_ID: 54, PARAM_REQUEST: 55, CLIENT_ID: 61, END: 255,
};
// What we ask for: mask, router, DNS, domain, lease time, server identifier —
// the six a technician reads off an offer.
const PARAM_REQUEST_LIST = [OPT.SUBNET_MASK, OPT.ROUTER, OPT.DNS, OPT.DOMAIN_NAME, OPT.LEASE_TIME, OPT.SERVER_ID];

const DEFAULT_TIMEOUT_MS = 3000;
const MIN_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 10000;
// More offers than this for one DISCOVER is already a finding; the rest add
// nothing an operator can act on, and every one is stored.
const MAX_OFFERS = 8;
const MAX_DNS = 4;

// --- codec (pure) -------------------------------------------------------------

// "aa:bb:cc:dd:ee:ff" → 6-byte Buffer, or null.
function macToBuffer(mac) {
  const s = String(mac || '').trim();
  if (!/^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i.test(s)) return null;
  return Buffer.from(s.split(/[:-]/).map((h) => parseInt(h, 16)));
}

const ipAt = (buf, off) => `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;

// Builds a DHCPDISCOVER. `mac` is a 6-byte Buffer (or "aa:bb:…" string), `xid`
// a 32-bit unsigned integer. The broadcast flag is set so the server answers to
// 255.255.255.255 — we already HAVE an address, and a unicast reply to a yiaddr
// that is not ours would never arrive.
function buildDiscover({ xid, mac }) {
  const hw = Buffer.isBuffer(mac) ? mac : macToBuffer(mac);
  if (!hw || hw.length !== 6) throw new Error('buildDiscover needs a 6-byte MAC');
  const options = [
    OPT.MESSAGE_TYPE, 1, MSG.DISCOVER,
    OPT.PARAM_REQUEST, PARAM_REQUEST_LIST.length, ...PARAM_REQUEST_LIST,
    // Client identifier (RFC 2132 §9.14): hardware type + MAC, which is what
    // most clients send, so a server keyed on it treats us like any other client.
    OPT.CLIENT_ID, 7, HTYPE_ETHERNET, ...hw,
    OPT.END,
  ];
  const len = Math.max(MIN_PACKET_LEN, OPTIONS_OFFSET + options.length);
  const buf = Buffer.alloc(len); // zero-filled: secs, ciaddr…giaddr, sname, file, padding
  buf[0] = BOOTREQUEST;
  buf[1] = HTYPE_ETHERNET;
  buf[2] = 6; // hlen
  buf[3] = 0; // hops
  buf.writeUInt32BE(xid >>> 0, 4);
  buf.writeUInt16BE(0, 8); // secs
  buf.writeUInt16BE(FLAG_BROADCAST, 10);
  hw.copy(buf, 28); // chaddr (16 bytes, the rest stays zero)
  MAGIC_COOKIE.copy(buf, FIXED_LEN);
  Buffer.from(options).copy(buf, OPTIONS_OFFSET);
  return buf;
}

// Walks one option area into `out` (code → Buffer). The first occurrence of a
// code wins, except that RFC 3396 long options split into several instances are
// concatenated. Returns false on a truncated option — the caller keeps whatever
// was read before it.
function readOptions(buf, start, end, out) {
  let i = start;
  while (i < end) {
    const code = buf[i];
    if (code === OPT.PAD) { i += 1; continue; }
    if (code === OPT.END) return true;
    if (i + 1 >= end) return false;
    const len = buf[i + 1];
    if (i + 2 + len > end) return false;
    const val = buf.subarray(i + 2, i + 2 + len);
    out.set(code, out.has(code) ? Buffer.concat([out.get(code), val]) : Buffer.from(val));
    i += 2 + len;
  }
  return true;
}

// Parses a BOOTP/DHCP message. Returns null for anything that is not one (too
// short, wrong magic cookie) — a stray datagram on port 68 must not crash the
// collector. Honours option 52 (overload), where a server may continue its
// options in the `file` and/or `sname` fields.
function parseDhcpPacket(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < OPTIONS_OFFSET) return null;
  if (!buf.subarray(FIXED_LEN, OPTIONS_OFFSET).equals(MAGIC_COOKIE)) return null;
  const hlen = Math.min(buf[2], 16);
  const options = new Map();
  readOptions(buf, OPTIONS_OFFSET, buf.length, options);
  const overload = options.has(OPT.OVERLOAD) ? options.get(OPT.OVERLOAD)[0] : 0;
  if (overload === 1 || overload === 3) readOptions(buf, 108, 236, options); // file
  if (overload === 2 || overload === 3) readOptions(buf, 44, 108, options); // sname
  const mt = options.get(OPT.MESSAGE_TYPE);
  return {
    op: buf[0],
    htype: buf[1],
    hlen,
    hops: buf[3],
    xid: buf.readUInt32BE(4),
    flags: buf.readUInt16BE(10),
    ciaddr: ipAt(buf, 12),
    yiaddr: ipAt(buf, 16),
    siaddr: ipAt(buf, 20),
    giaddr: ipAt(buf, 24),
    chaddr: buf.subarray(28, 28 + hlen),
    messageType: mt && mt.length ? mt[0] : null,
    options,
  };
}

// An option that holds one or more IPv4 addresses → ['a.b.c.d', …].
function ipList(val) {
  const out = [];
  if (!val) return out;
  for (let i = 0; i + 4 <= val.length; i += 4) out.push(ipAt(val, i));
  return out;
}

// One offer, in the shape the server stores. `relay` is giaddr — non-null
// when the offer came through a relay agent (ip helper-address), which is the
// clue that the answering server is not on this segment at all.
function offerFromPacket(p) {
  const o = p.options;
  const one = (code) => { const l = ipList(o.get(code)); return l.length ? l[0] : null; };
  const lease = o.get(OPT.LEASE_TIME);
  const nz = (ip) => (ip && ip !== '0.0.0.0' ? ip : null);
  return {
    serverId: one(OPT.SERVER_ID),
    offeredIp: nz(p.yiaddr),
    leaseSec: lease && lease.length >= 4 ? lease.readUInt32BE(0) : null,
    router: one(OPT.ROUTER),
    dns: ipList(o.get(OPT.DNS)).slice(0, MAX_DNS),
    subnetMask: one(OPT.SUBNET_MASK),
    relay: nz(p.giaddr),
  };
}

// Is this parsed packet an OFFER to OUR discover? Same xid, a reply, and (when
// the server echoed one) our hardware address — another client's exchange on
// the same broadcast domain must not be counted as an answer to ours.
function isOfferFor(p, { xid, mac }) {
  if (!p || p.op !== BOOTREPLY || p.xid !== (xid >>> 0)) return false;
  if (p.messageType !== MSG.OFFER) return false;
  if (mac && p.hlen === 6 && !p.chaddr.equals(mac)) return false;
  return true;
}

// --- interface selection ------------------------------------------------------

function defaultReadRoute() {
  return fs.readFileSync('/proc/net/route', 'utf8');
}

// The interface the DISCOVER speaks for: `spec.iface` when given, otherwise the
// default-route interface (Linux), otherwise the first non-internal interface
// with an IPv4 address. Returns { iface, mac } or { error }.
function chooseInterface(requested, { networkInterfaces = os.networkInterfaces, readRoute = defaultReadRoute } = {}) {
  let table;
  try { table = networkInterfaces() || {}; } catch { table = {}; }
  const usable = (name) => {
    const addrs = Array.isArray(table[name]) ? table[name] : [];
    const v4 = addrs.find((a) => a && (a.family === 'IPv4' || a.family === 4) && !a.internal);
    if (!v4) return null;
    const mac = macToBuffer(v4.mac);
    if (!mac || mac.every((b) => b === 0)) return null;
    return { iface: name, mac, address: v4.address };
  };
  if (requested) {
    if (!table[requested]) return { error: `interface ${requested} not found on this host` };
    return usable(requested) || { error: `no IPv4 interface: ${requested} has no IPv4 address (or no hardware address)` };
  }
  let routeIface = null;
  try { routeIface = defaultRouteInterface(readRoute()); } catch { /* no /proc/net/route (non-Linux) */ }
  if (routeIface && usable(routeIface)) return usable(routeIface);
  for (const name of Object.keys(table)) {
    const u = usable(name);
    if (u) return u;
  }
  return { error: 'no IPv4 interface with a hardware address to send a DHCPDISCOVER from' };
}

// --- runner ---------------------------------------------------------------------

const PERMISSION_ERROR = 'dhcp probe needs root or CAP_NET_BIND_SERVICE (port 68)';

function bindClientSocket(createSocket, reuseAddr) {
  return new Promise((resolve, reject) => {
    let sock;
    try { sock = createSocket({ type: 'udp4', reuseAddr }); } catch (err) { reject(err); return; }
    const onError = (err) => { try { sock.close(); } catch { /* already closed */ } reject(err); };
    sock.once('error', onError);
    try {
      sock.bind({ port: CLIENT_PORT, address: '0.0.0.0' }, () => {
        sock.removeListener('error', onError);
        resolve(sock);
      });
    } catch (err) { onError(err); }
  });
}

// Port 68 is the DHCP client's port, so the host's own DHCP client may hold it.
// First try on our own; on EADDRINUSE try again sharing it (SO_REUSEADDR — the
// kernel then delivers each broadcast reply to every socket bound there, which
// is exactly what we need), and only then give up with a reason that says who.
async function openSocket(createSocket) {
  try {
    return { sock: await bindClientSocket(createSocket, false) };
  } catch (err) {
    if (err && (err.code === 'EACCES' || err.code === 'EPERM')) return { error: PERMISSION_ERROR };
    if (!err || err.code !== 'EADDRINUSE') return { error: `dhcp probe could not open UDP port 68: ${err ? err.message : 'unknown error'}` };
  }
  try {
    return { sock: await bindClientSocket(createSocket, true) };
  } catch (err) {
    if (err && (err.code === 'EACCES' || err.code === 'EPERM')) return { error: PERMISSION_ERROR };
    return { error: 'UDP port 68 is in use by another DHCP client on this host (dhclient / systemd-networkd / NetworkManager) and could not be shared (EADDRINUSE)' };
  }
}

const round = (n) => Math.round(n * 100) / 100;

// Runs one DHCP test.
//   spec: { type:'dhcp', iface?, timeoutMs?|timeout_ms? }
//   deps: { createSocket, networkInterfaces, readRoute, now, randomXid, setTimer, clearTimer }
// Result: the normalized probe record (`target` = the interface) plus
//   iface, timeoutMs, offers[] (≤8), serverCount (distinct server identifiers).
// ok = at least one offer. "No offer" is a MEASUREMENT (ok:false, lossPct 100,
// offers: []), not an `error` — `error` is reserved for "could not run at all"
// (no permission, no interface), which is how the server tells the two apart.
async function dhcpProbe(spec = {}, deps = {}) {
  const {
    createSocket = dgram.createSocket,
    now = () => Number(process.hrtime.bigint()) / 1e6,
    randomXid = () => crypto.randomBytes(4).readUInt32BE(0),
    // The collection window. Injectable so a test of a 10 s timeout does not
    // take 10 s; production uses the real timer.
    setTimer = setTimeout,
    clearTimer = clearTimeout,
  } = deps;
  const requested = spec.iface != null && String(spec.iface).trim() ? String(spec.iface).trim() : null;
  const raw = Number(spec.timeoutMs ?? spec.timeout_ms);
  const timeoutMs = Number.isFinite(raw) ? Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, Math.round(raw))) : DEFAULT_TIMEOUT_MS;

  const base = {
    type: 'dhcp', target: requested || 'default', ok: false, attempts: 1, success: 0,
    rttMs: null, minMs: null, maxMs: null, jitterMs: null, lossPct: 100,
    iface: requested, timeoutMs,
  };
  const chosen = chooseInterface(requested, deps);
  if (chosen.error) return { ...base, error: chosen.error };
  base.target = chosen.iface;
  base.iface = chosen.iface;

  const opened = await openSocket(createSocket);
  if (opened.error) return { ...base, error: opened.error };
  const { sock } = opened;

  const xid = randomXid() >>> 0;
  const packet = buildDiscover({ xid, mac: chosen.mac });
  const offers = [];
  const rtts = [];
  let sentAt = null;

  return new Promise((resolve) => {
    let finished = false;
    let timer = null;
    const finish = (extra = {}) => {
      if (finished) return;
      finished = true;
      if (timer) clearTimer(timer);
      try { sock.close(); } catch { /* already closed */ }
      const serverIds = [...new Set(offers.map((o) => o.serverId).filter(Boolean))];
      const ok = offers.length > 0;
      resolve({
        ...base,
        ok,
        success: ok ? 1 : 0,
        lossPct: ok ? 0 : 100,
        rttMs: rtts.length ? round(rtts[0]) : null,
        minMs: rtts.length ? round(Math.min(...rtts)) : null,
        maxMs: rtts.length ? round(Math.max(...rtts)) : null,
        offers,
        // Distinct server identifiers. An offer with no option 54 (a broken
        // server) still counts once, so it is not invisible in the verdict.
        serverCount: serverIds.length + (offers.some((o) => !o.serverId) ? 1 : 0),
        ...(ok || extra.error ? {} : { detail: `no DHCPOFFER on ${chosen.iface} within ${timeoutMs} ms` }),
        ...extra,
      });
    };

    sock.on('message', (msg) => {
      if (finished || sentAt === null) return;
      const p = parseDhcpPacket(msg);
      if (!isOfferFor(p, { xid, mac: chosen.mac })) return;
      // The same server answering twice (retransmit, or reached through two
      // relays) is one server; the offers list keeps the first of each.
      const offer = offerFromPacket(p);
      const dup = offers.some((o) => o.serverId === offer.serverId && o.offeredIp === offer.offeredIp && o.relay === offer.relay);
      if (dup || offers.length >= MAX_OFFERS) return;
      offers.push(offer);
      rtts.push(now() - sentAt);
    });
    // A socket error after offers arrived still leaves a measurement; only an
    // exchange that produced nothing is a probe that could not run.
    sock.on('error', (err) => finish(offers.length ? {} : { error: `dhcp probe socket error: ${err.message}` }));

    try { sock.setBroadcast(true); } catch (err) { finish({ error: `dhcp probe could not enable broadcast: ${err.message}` }); return; }
    sentAt = now();
    sock.send(packet, 0, packet.length, SERVER_PORT, BROADCAST, (err) => {
      if (err) {
        const msg = err.code === 'EACCES' || err.code === 'EPERM' ? PERMISSION_ERROR : `dhcp probe could not send DHCPDISCOVER: ${err.message}`;
        finish({ error: msg });
      }
    });
    timer = setTimer(() => finish(), timeoutMs);
  });
}

module.exports = {
  dhcpProbe,
  buildDiscover,
  parseDhcpPacket,
  offerFromPacket,
  isOfferFor,
  chooseInterface,
  macToBuffer,
  MSG,
  OPT,
  PARAM_REQUEST_LIST,
  MAX_OFFERS,
  DEFAULT_TIMEOUT_MS,
  MIN_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  PERMISSION_ERROR,
};
