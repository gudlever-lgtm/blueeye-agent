'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');

const {
  dhcpProbe, buildDiscover, parseDhcpPacket, offerFromPacket, isOfferFor, chooseInterface,
  MSG, PARAM_REQUEST_LIST, PERMISSION_ERROR, MAX_OFFERS,
} = require('../src/probes/dhcp');
const { runProbe, PROBE_TYPES } = require('../src/probes');
const { parseConfiguredTargets, resolveProbeTargets } = require('../src/probes/targets');

const MAC = Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const XID = 0x3903f326;

// A DHCPOFFER byte for byte as RFC 2131 §2 lays it out — written out by hand
// here rather than with the module's own encoder, so the parser is checked
// against the wire format and not against itself.
function realOffer({
  xid = XID, chaddr = MAC, yiaddr = [192, 168, 1, 100], giaddr = [0, 0, 0, 0],
  serverId = [192, 168, 1, 1], router = [192, 168, 1, 1], dns = [[192, 168, 1, 1], [9, 9, 9, 9]],
  lease = 86400, mask = [255, 255, 255, 0], messageType = 2, extraOptions = [], sname = null, file = null,
} = {}) {
  const b = Buffer.alloc(236);
  b[0] = 2; // op BOOTREPLY
  b[1] = 1; // htype ethernet
  b[2] = 6; // hlen
  b[3] = giaddr[0] ? 1 : 0; // hops
  b.writeUInt32BE(xid, 4);
  b.writeUInt16BE(0, 8); // secs
  b.writeUInt16BE(0x8000, 10); // flags: broadcast
  Buffer.from([0, 0, 0, 0]).copy(b, 12); // ciaddr
  Buffer.from(yiaddr).copy(b, 16); // yiaddr
  Buffer.from(serverId).copy(b, 20); // siaddr (next server)
  Buffer.from(giaddr).copy(b, 24); // giaddr
  chaddr.copy(b, 28); // chaddr, 16 bytes with 10 of padding
  if (sname) Buffer.from(sname).copy(b, 44);
  if (file) Buffer.from(file).copy(b, 108);
  const leaseBytes = Buffer.alloc(4); leaseBytes.writeUInt32BE(lease);
  const opts = [
    53, 1, messageType,
    54, 4, ...serverId,
    51, 4, ...leaseBytes,
    1, 4, ...mask,
    3, 4, ...router,
    6, dns.length * 4, ...dns.flat(),
    ...extraOptions,
    255,
  ];
  return Buffer.concat([b, Buffer.from([99, 130, 83, 99]), Buffer.from(opts), Buffer.alloc(12)]);
}

test('buildDiscover: an RFC 2131 DHCPDISCOVER — broadcast flag, xid, chaddr, cookie, options 53/55/61', () => {
  const p = buildDiscover({ xid: XID, mac: MAC });
  assert.ok(p.length >= 300, 'padded to the BOOTP minimum');
  assert.equal(p[0], 1); // BOOTREQUEST
  assert.equal(p[1], 1); // ethernet
  assert.equal(p[2], 6);
  assert.equal(p.readUInt32BE(4), XID);
  assert.equal(p.readUInt16BE(10), 0x8000);
  assert.deepEqual([...p.subarray(12, 28)], new Array(16).fill(0), 'ciaddr/yiaddr/siaddr/giaddr are zero');
  assert.ok(p.subarray(28, 34).equals(MAC));
  assert.deepEqual([...p.subarray(236, 240)], [99, 130, 83, 99]);
  const parsed = parseDhcpPacket(p);
  assert.equal(parsed.messageType, MSG.DISCOVER);
  assert.deepEqual([...parsed.options.get(55)], [1, 3, 6, 15, 51, 54]);
  assert.deepEqual(PARAM_REQUEST_LIST, [1, 3, 6, 15, 51, 54]);
  assert.deepEqual([...parsed.options.get(61)], [1, ...MAC]);
  // Never a REQUEST: the discover is the only thing this module can build.
  assert.ok(!parsed.options.has(50), 'no requested-IP option');
});

test('buildDiscover accepts a colon MAC string and refuses a malformed one', () => {
  assert.ok(buildDiscover({ xid: 1, mac: '52:54:00:12:34:56' }).subarray(28, 34).equals(MAC));
  assert.throws(() => buildDiscover({ xid: 1, mac: 'nope' }));
});

test('parseDhcpPacket + offerFromPacket read a hand-built DHCPOFFER', () => {
  const p = parseDhcpPacket(realOffer());
  assert.equal(p.op, 2);
  assert.equal(p.xid, XID);
  assert.equal(p.messageType, MSG.OFFER);
  assert.equal(p.yiaddr, '192.168.1.100');
  assert.deepEqual(offerFromPacket(p), {
    serverId: '192.168.1.1',
    offeredIp: '192.168.1.100',
    leaseSec: 86400,
    router: '192.168.1.1',
    dns: ['192.168.1.1', '9.9.9.9'],
    subnetMask: '255.255.255.0',
    relay: null,
  });
});

test('offerFromPacket names the relay (giaddr) when the offer came through one', () => {
  const o = offerFromPacket(parseDhcpPacket(realOffer({ giaddr: [10, 20, 0, 1], serverId: [10, 0, 0, 5] })));
  assert.equal(o.relay, '10.20.0.1');
  assert.equal(o.serverId, '10.0.0.5');
});

test('parseDhcpPacket honours option 52 (overload) into the file field', () => {
  // Server-id moved into `file` because the options field ran out.
  const buf = realOffer({ extraOptions: [52, 1, 1], serverId: [0, 0, 0, 0], file: [54, 4, 172, 16, 0, 1, 255] });
  // The main options area still carries option 54 = 0.0.0.0 (first wins), so
  // build one without it to see the overload path.
  const p = parseDhcpPacket(buf);
  assert.equal(p.options.get(52)[0], 1);
  const noSid = Buffer.from(buf);
  // Rewrite the main-area option 54 into a pad run.
  const at = noSid.indexOf(Buffer.from([54, 4, 0, 0, 0, 0]), 240);
  noSid.fill(0, at, at + 6);
  assert.equal(offerFromPacket(parseDhcpPacket(noSid)).serverId, '172.16.0.1');
});

test('parseDhcpPacket rejects junk, short packets and a wrong magic cookie', () => {
  assert.equal(parseDhcpPacket(Buffer.alloc(10)), null);
  assert.equal(parseDhcpPacket('nope'), null);
  const bad = realOffer();
  bad[236] = 0;
  assert.equal(parseDhcpPacket(bad), null);
  // A truncated option keeps what was read before it, instead of throwing.
  const trunc = realOffer().subarray(0, 245);
  const p = parseDhcpPacket(trunc);
  assert.equal(p.messageType, 2);
});

test('isOfferFor: same xid, BOOTREPLY, OFFER, our chaddr — nothing else counts', () => {
  const ctx = { xid: XID, mac: MAC };
  assert.equal(isOfferFor(parseDhcpPacket(realOffer()), ctx), true);
  assert.equal(isOfferFor(parseDhcpPacket(realOffer({ xid: 7 })), ctx), false);
  assert.equal(isOfferFor(parseDhcpPacket(realOffer({ messageType: 5 })), ctx), false, 'an ACK is not an offer');
  assert.equal(isOfferFor(parseDhcpPacket(realOffer({ chaddr: Buffer.from([1, 2, 3, 4, 5, 6]) })), ctx), false);
  assert.equal(isOfferFor(null, ctx), false);
});

// --- runner, with an injected socket -------------------------------------------

const IFACES = {
  lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, mac: '00:00:00:00:00:00' }],
  eth0: [{ address: '192.168.1.50', family: 'IPv4', internal: false, mac: '52:54:00:12:34:56' }],
  eth1: [{ address: 'fe80::1', family: 'IPv6', internal: false, mac: '52:54:00:aa:bb:cc' }],
};
const ROUTE = 'Iface\tDestination\tGateway\tFlags\nlo\t0000007F\t00000000\t0001\neth0\t00000000\t0101A8C0\t0003\n';

// A fake dgram socket. `onSend(packet, sock)` scripts the network's answer.
function fakeDgram({ bindError = null, bindErrorReuse = null, onSend = () => {}, sendError = null } = {}) {
  const calls = { created: [], sent: [], closed: 0, broadcast: false };
  const createSocket = (opts) => {
    const sock = new EventEmitter();
    calls.created.push(opts);
    sock.bind = (o, cb) => {
      const err = opts.reuseAddr ? bindErrorReuse : bindError;
      if (err) setImmediate(() => sock.emit('error', Object.assign(new Error(err), { code: err })));
      else { calls.bound = o; setImmediate(cb); }
    };
    sock.setBroadcast = (v) => { calls.broadcast = v; };
    sock.send = (buf, off, len, port, addr, cb) => {
      calls.sent.push({ buf: Buffer.from(buf), port, addr });
      if (sendError) { setImmediate(() => cb(Object.assign(new Error(sendError), { code: sendError }))); return; }
      setImmediate(() => cb(null));
      onSend(buf, sock);
    };
    sock.close = () => { calls.closed += 1; };
    return sock;
  };
  return { createSocket, calls };
}

const timers = [];
const deps = (dg, extra = {}) => ({
  createSocket: dg.createSocket,
  networkInterfaces: () => IFACES,
  readRoute: () => ROUTE,
  randomXid: () => XID,
  now: (() => { let t = 1000; return () => { t += 7; return t; }; })(),
  // The window closes after the scripted answers have been delivered, whatever
  // the configured timeout — the tests assert the bound, not wait it out.
  setTimer: (fn, ms) => { timers.push(ms); return setTimeout(fn, 20); },
  clearTimer: (h) => clearTimeout(h),
  ...extra,
});

test('dhcpProbe: one offer → ok, rtt, offer detail, serverCount 1; broadcast from 0.0.0.0:68 to 255.255.255.255:67', async () => {
  const dg = fakeDgram({ onSend: (buf, sock) => setImmediate(() => sock.emit('message', realOffer({ xid: buf.readUInt32BE(4) }))) });
  const r = await dhcpProbe({ type: 'dhcp', timeoutMs: 1000 }, deps(dg));
  assert.equal(r.ok, true);
  assert.equal(r.type, 'dhcp');
  assert.equal(r.target, 'eth0');
  assert.equal(r.iface, 'eth0');
  assert.equal(r.serverCount, 1);
  assert.equal(r.offers.length, 1);
  assert.equal(r.offers[0].offeredIp, '192.168.1.100');
  assert.equal(r.lossPct, 0);
  assert.ok(r.rttMs > 0);
  assert.equal(r.error, undefined);
  assert.equal(dg.calls.sent.length, 1, 'exactly one packet: the DISCOVER — never a REQUEST');
  assert.equal(parseDhcpPacket(dg.calls.sent[0].buf).messageType, MSG.DISCOVER);
  assert.equal(dg.calls.sent[0].port, 67);
  assert.equal(dg.calls.sent[0].addr, '255.255.255.255');
  assert.deepEqual(dg.calls.bound, { port: 68, address: '0.0.0.0' });
  assert.equal(dg.calls.broadcast, true);
  assert.ok(dg.calls.sent[0].buf.subarray(28, 34).equals(MAC), 'chaddr = the default-route interface MAC');
  assert.equal(dg.calls.closed, 1);
});

test('dhcpProbe: two servers answering → serverCount 2 (the rogue-server signal); strays and duplicates ignored', async () => {
  const dg = fakeDgram({
    onSend: (buf, sock) => setImmediate(() => {
      sock.emit('message', realOffer());
      sock.emit('message', realOffer()); // retransmit of the same offer
      sock.emit('message', realOffer({ xid: 99 })); // somebody else's exchange
      sock.emit('message', Buffer.from('garbage'));
      sock.emit('message', realOffer({ serverId: [192, 168, 1, 66], router: [192, 168, 1, 66], yiaddr: [192, 168, 1, 201] }));
    }),
  });
  const r = await dhcpProbe({ type: 'dhcp', timeoutMs: 1000 }, deps(dg));
  assert.equal(r.ok, true);
  assert.equal(r.offers.length, 2);
  assert.equal(r.serverCount, 2);
  assert.deepEqual(r.offers.map((o) => o.serverId), ['192.168.1.1', '192.168.1.66']);
});

test('dhcpProbe: offers are bounded', async () => {
  const dg = fakeDgram({
    onSend: (buf, sock) => setImmediate(() => {
      for (let i = 1; i <= 12; i += 1) sock.emit('message', realOffer({ serverId: [10, 0, 0, i] }));
    }),
  });
  const r = await dhcpProbe({ type: 'dhcp', timeoutMs: 1000 }, deps(dg));
  assert.equal(r.offers.length, MAX_OFFERS);
});

test('dhcpProbe: no answer → ok:false, offers [], a detail and NO error (it ran; nobody answered)', async () => {
  const dg = fakeDgram();
  const r = await dhcpProbe({ type: 'dhcp', iface: 'eth0', timeoutMs: 1000 }, deps(dg));
  assert.equal(r.ok, false);
  assert.deepEqual(r.offers, []);
  assert.equal(r.serverCount, 0);
  assert.equal(r.lossPct, 100);
  assert.equal(r.error, undefined);
  assert.match(r.detail, /no DHCPOFFER on eth0 within 1000 ms/);
});

test('dhcpProbe: timeout is bounded 1–10 s', async () => {
  const dg = fakeDgram({ onSend: (buf, sock) => setImmediate(() => sock.emit('message', realOffer())) });
  assert.equal((await dhcpProbe({ timeoutMs: 50 }, deps(dg))).timeoutMs, 1000);
  assert.equal((await dhcpProbe({ timeout_ms: 60000 }, deps(dg))).timeoutMs, 10000);
  assert.equal((await dhcpProbe({}, deps(dg))).timeoutMs, 3000);
  assert.deepEqual(timers.slice(-3), [1000, 10000, 3000], 'the collection window is the bounded timeout');
});

test('dhcpProbe: EACCES/EPERM on port 68 names root / CAP_NET_BIND_SERVICE', async () => {
  for (const code of ['EACCES', 'EPERM']) {
    const r = await dhcpProbe({}, deps(fakeDgram({ bindError: code })));
    assert.equal(r.ok, false);
    assert.equal(r.error, PERMISSION_ERROR);
    assert.match(r.error, /root or CAP_NET_BIND_SERVICE \(port 68\)/);
  }
});

test('dhcpProbe: EADDRINUSE retries with reuseAddr, and succeeds when the port can be shared', async () => {
  const dg = fakeDgram({ bindError: 'EADDRINUSE', onSend: (buf, sock) => setImmediate(() => sock.emit('message', realOffer())) });
  const r = await dhcpProbe({ timeoutMs: 1000 }, deps(dg));
  assert.equal(r.ok, true);
  assert.deepEqual(dg.calls.created.map((o) => o.reuseAddr), [false, true]);
});

test('dhcpProbe: EADDRINUSE that cannot be shared names the other DHCP client', async () => {
  const r = await dhcpProbe({}, deps(fakeDgram({ bindError: 'EADDRINUSE', bindErrorReuse: 'EADDRINUSE' })));
  assert.equal(r.ok, false);
  assert.match(r.error, /port 68 is in use by another DHCP client/);
  assert.match(r.error, /EADDRINUSE/);
});

test('dhcpProbe: no IPv4 interface → error, nothing sent', async () => {
  const dg = fakeDgram();
  const r = await dhcpProbe({ iface: 'eth1' }, deps(dg));
  assert.equal(r.ok, false);
  assert.match(r.error, /no IPv4 interface/);
  assert.equal(dg.calls.created.length, 0);
  const r2 = await dhcpProbe({ iface: 'wlan9' }, deps(dg));
  assert.match(r2.error, /not found/);
  const r3 = await dhcpProbe({}, deps(dg, { networkInterfaces: () => ({ lo: IFACES.lo }) }));
  assert.match(r3.error, /no IPv4 interface/);
});

test('dhcpProbe: a send failure is reported as an error', async () => {
  const r = await dhcpProbe({ timeoutMs: 1000 }, deps(fakeDgram({ sendError: 'ENETUNREACH' })));
  assert.equal(r.ok, false);
  assert.match(r.error, /could not send DHCPDISCOVER/);
});

test('chooseInterface: default route first, then the first usable interface', () => {
  assert.equal(chooseInterface(null, { networkInterfaces: () => IFACES, readRoute: () => ROUTE }).iface, 'eth0');
  const noRoute = chooseInterface(null, { networkInterfaces: () => IFACES, readRoute: () => { throw new Error('ENOENT'); } });
  assert.equal(noRoute.iface, 'eth0');
});

test('runProbe dispatches dhcp and never throws', async () => {
  assert.ok(PROBE_TYPES.includes('dhcp'));
  const dg = fakeDgram({ onSend: (buf, sock) => setImmediate(() => sock.emit('message', realOffer())) });
  const r = await runProbe({ type: 'dhcp', timeoutMs: 1000 }, { dhcp: deps(dg) });
  assert.equal(r.type, 'dhcp');
  assert.equal(r.ok, true);
  assert.ok(r.ts);
});

test('configured targets: "dhcp" and "dhcp:<iface>" are schedulable, and nothing is on by default', async () => {
  assert.deepEqual(parseConfiguredTargets('dhcp'), [{ type: 'dhcp' }]);
  assert.deepEqual(parseConfiguredTargets('ping:1.1.1.1,dhcp:eth0'), [{ type: 'ping', host: '1.1.1.1' }, { type: 'dhcp', iface: 'eth0' }]);
  assert.deepEqual(parseConfiguredTargets([{ type: 'dhcp', iface: 'eth1' }]), [{ type: 'dhcp', iface: 'eth1' }]);
  assert.deepEqual(parseConfiguredTargets('dhcp:-rf'), [], 'an interface name that could never exist is dropped');
  const specs = await resolveProbeTargets({
    configured: parseConfiguredTargets('dhcp,dhcp:eth0,dhcp'),
    readRoute: async () => ROUTE, readResolv: async () => '', platform: 'linux',
  });
  assert.deepEqual(specs.filter((s) => s.type === 'dhcp').map((s) => s.iface || null), [null, 'eth0'], 'deduplicated per interface');
  // The default schedule (gateway + DNS, no configured targets) has no DHCP test.
  const defaults = await resolveProbeTargets({ readRoute: async () => ROUTE, readResolv: async () => 'nameserver 192.168.1.1\n', platform: 'linux' });
  assert.ok(defaults.every((s) => s.type !== 'dhcp'));
});
