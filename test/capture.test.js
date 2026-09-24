'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { Readable } = require('stream');

const { createPcapParser } = require('../src/capture/pcapStream');
const { decodeFrame, LINKTYPE } = require('../src/capture/decode');
const { targetsForTest, buildFilter, tcpdumpArgs, MAX_TARGETS } = require('../src/capture/filter');
const { createCaptureRunner, detectCaptureSupport, observedPortsOf } = require('../src/capture');

// ---------------------------------------------------------------- fixtures

function globalHeader({ littleEndian = true, nanos = false, linkType = LINKTYPE.EN10MB } = {}) {
  const b = Buffer.alloc(24);
  const magic = littleEndian ? (nanos ? 0x4d3cb2a1 : 0xd4c3b2a1) : (nanos ? 0xa1b23c4d : 0xa1b2c3d4);
  b.writeUInt32BE(magic, 0);
  const w = (v, o) => (littleEndian ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o));
  w(96, 16);
  w(linkType, 20);
  return b;
}

function packetRecord(frame, { littleEndian = true, sec = 100, frac = 0 } = {}) {
  const h = Buffer.alloc(16);
  const w = (v, o) => (littleEndian ? h.writeUInt32LE(v, o) : h.writeUInt32BE(v, o));
  w(sec, 0); w(frac, 4); w(frame.length, 8); w(frame.length, 12);
  return Buffer.concat([h, frame]);
}

// Ethernet + IPv4 + TCP. `opts.mss` adds the MSS option (as a SYN would carry).
function tcpFrame({ src = '10.0.0.1', dst = '10.0.0.2', sport = 51234, dport = 443, flags = 0x02, seq = 1, ack = 0, win = 64240, mss = null, payload = 0 } = {}) {
  const dataOffset = mss != null ? 24 : 20;
  const b = Buffer.alloc(14 + 20 + dataOffset + payload);
  b.writeUInt16BE(0x0800, 12);
  b[14] = 0x45;
  b.writeUInt16BE(20 + dataOffset + payload, 16);
  b[14 + 8] = 64;
  b[14 + 9] = 6;
  src.split('.').forEach((o, i) => { b[14 + 12 + i] = Number(o); });
  dst.split('.').forEach((o, i) => { b[14 + 16 + i] = Number(o); });
  const l4 = 34;
  b.writeUInt16BE(sport, l4);
  b.writeUInt16BE(dport, l4 + 2);
  b.writeUInt32BE(seq, l4 + 4);
  b.writeUInt32BE(ack, l4 + 8);
  b[l4 + 12] = (dataOffset / 4) << 4;
  b[l4 + 13] = flags;
  b.writeUInt16BE(win, l4 + 14);
  if (mss != null) { b[l4 + 20] = 2; b[l4 + 21] = 4; b.writeUInt16BE(mss, l4 + 22); }
  return b;
}

// A fake tcpdump: a child-process shape whose stdout we drive by hand.
function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new Readable({ read() {} });
  child.stderr = new Readable({ read() {} });
  child.killed = false;
  child.signals = [];
  child.kill = (sig) => { child.killed = true; child.signals.push(sig); setImmediate(() => child.emit('close', 0)); return true; };
  child.write = (buf) => child.stdout.push(buf);
  return child;
}

function runnerWith(child, overrides = {}) {
  return createCaptureRunner({
    spawn: () => child,
    platform: 'linux',
    lookup: (host, opts, cb) => cb(null, host === 'app.kunde.dk' ? '10.0.0.2' : '10.0.0.9'),
    readFile: async () => 'nameserver 10.0.0.53\n',
    readProcNetRoute: async () => 'Iface\tDestination\neth0\t00000000\n',
    ...overrides,
  });
}

const HTTP_TEST = { id: 7, type: 'http', config: { steps: [{ url: 'https://app.kunde.dk/login' }] } };

// ---------------------------------------------------------------- decode

test('decode: reads the TCP header fields a fault diagnosis needs', () => {
  const rec = decodeFrame(tcpFrame({ flags: 0x02, mss: 1460 }), { tsMs: 5, wireLen: 78 });
  assert.equal(rec.src, '10.0.0.1');
  assert.equal(rec.dst, '10.0.0.2');
  assert.equal(rec.sport, 51234);
  assert.equal(rec.dport, 443);
  assert.equal(rec.flags, 'S');
  assert.equal(rec.win, 64240);
  assert.equal(rec.mss, 1460);
  assert.equal(rec.ttl, 64);
  assert.equal(rec.len, 78, 'reports the WIRE length, not the captured length');
});

test('decode: flag letters match what a reset and a data segment look like', () => {
  assert.equal(decodeFrame(tcpFrame({ flags: 0x04 }), {}).flags, 'R');
  assert.equal(decodeFrame(tcpFrame({ flags: 0x12 }), {}).flags, 'SA');
  assert.equal(decodeFrame(tcpFrame({ flags: 0x18, payload: 100 }), {}).payload, 100);
});

test('decode: carries no payload bytes, only their count', () => {
  const frame = tcpFrame({ flags: 0x18, payload: 40 });
  frame.fill(0x41, frame.length - 40); // 'AAAA…' where a body would be
  const rec = decodeFrame(frame, {});
  const asText = JSON.stringify(rec);
  assert.ok(!asText.includes('AAAA'), 'no payload bytes reach the record');
  assert.equal(rec.payload, 40, 'the byte COUNT is kept');
});

test('decode: a truncated frame yields null rather than a half-read record', () => {
  assert.equal(decodeFrame(tcpFrame().subarray(0, 20), {}), null);
  assert.equal(decodeFrame(Buffer.alloc(2), {}), null);
});

test('decode: non-IP frames are dropped (ARP, STP and the rest)', () => {
  const arp = Buffer.alloc(42);
  arp.writeUInt16BE(0x0806, 12);
  assert.equal(decodeFrame(arp, {}), null);
});

test('decode: reads Linux cooked captures, which `-i any` produces', () => {
  const inner = tcpFrame().subarray(14); // strip Ethernet
  const sll = Buffer.concat([Buffer.alloc(16), inner]);
  sll.writeUInt16BE(0x0800, 14);
  const rec = decodeFrame(sll, { linkType: LINKTYPE.LINUX_SLL });
  assert.equal(rec.dport, 443);

  const sll2 = Buffer.concat([Buffer.alloc(20), inner]);
  sll2.writeUInt16BE(0x0800, 0);
  assert.equal(decodeFrame(sll2, { linkType: LINKTYPE.LINUX_SLL2 }).dport, 443);
});

test('decode: a malformed TCP option length ends the walk instead of spinning', () => {
  const f = tcpFrame({ mss: 1460 });
  f[34 + 21] = 0; // option length 0 — would loop forever if trusted
  const rec = decodeFrame(f, {});
  assert.equal(rec.mss, null);
  assert.equal(rec.flags, 'S', 'the rest of the header still reads');
});

// ---------------------------------------------------------------- pcapStream

test('pcapStream: reassembles frames across arbitrary chunk boundaries', () => {
  const parser = createPcapParser();
  const stream = Buffer.concat([
    globalHeader(),
    packetRecord(tcpFrame(), { sec: 100, frac: 0 }),
    packetRecord(tcpFrame({ flags: 0x12 }), { sec: 100, frac: 31000 }),
  ]);
  let out = [];
  for (const byte of stream) out = out.concat(parser.push(Buffer.from([byte])));
  assert.equal(out.length, 2);
  assert.equal(parser.linkType(), LINKTYPE.EN10MB);
  assert.equal(Math.round(out[1].tsMs), 31, 'microsecond timestamps scale to ms');
});

test('pcapStream: nanosecond captures scale the same', () => {
  const parser = createPcapParser();
  parser.push(globalHeader({ nanos: true }));
  const [rec] = parser.push(packetRecord(tcpFrame(), { sec: 100, frac: 0 }))
    .concat(parser.push(packetRecord(tcpFrame(), { sec: 100, frac: 31000000 })));
  assert.ok(rec);
  const second = parser.push(Buffer.alloc(0));
  assert.equal(second.length, 0);
});

test('pcapStream: both byte orders are accepted', () => {
  for (const littleEndian of [true, false]) {
    const parser = createPcapParser();
    parser.push(globalHeader({ littleEndian }));
    const out = parser.push(packetRecord(tcpFrame(), { littleEndian }));
    assert.equal(out.length, 1, `byte order littleEndian=${littleEndian}`);
  }
});

test('pcapStream: an implausible frame length stops the parse, it does not allocate', () => {
  const parser = createPcapParser();
  parser.push(globalHeader());
  const bad = Buffer.alloc(16);
  bad.writeUInt32LE(100, 0); bad.writeUInt32LE(0, 4);
  bad.writeUInt32LE(0x7fffffff, 8); bad.writeUInt32LE(0x7fffffff, 12);
  assert.deepEqual(parser.push(bad), []);
  assert.match(parser.error(), /implausible frame length/);
});

test('pcapStream: an unknown magic is refused rather than guessed at', () => {
  const parser = createPcapParser();
  const junk = Buffer.alloc(24);
  junk.writeUInt32BE(0xdeadbeef, 0);
  assert.deepEqual(parser.push(junk), []);
  assert.match(parser.error(), /unrecognised pcap magic/);
});

// ---------------------------------------------------------------- filter

test('filter: http targets come from the step URLs, with the scheme default port', () => {
  const targets = targetsForTest({
    type: 'http',
    config: { steps: [{ url: 'https://app.kunde.dk/login' }, { url: 'http://legacy.kunde.dk:8080/x' }] },
  });
  assert.deepEqual(targets, [
    { host: 'app.kunde.dk', port: 443, proto: 'tcp' },
    { host: 'legacy.kunde.dk', port: 8080, proto: 'tcp' },
  ]);
});

test('filter: a URL still holding a placeholder is skipped, never guessed', () => {
  const targets = targetsForTest({ type: 'http', config: { steps: [{ url: 'https://{{secret:host}}/x' }] } });
  assert.deepEqual(targets, [], 'a placeholder host would filter on the wrong machine');
});

test('filter: a dns test captures towards the RESOLVER, not the name looked up', () => {
  const targets = targetsForTest({ type: 'dns', target: 'example.dk', config: {} }, { resolvers: ['10.0.0.53'] });
  assert.deepEqual(targets, [{ host: '10.0.0.53', port: 53, proto: 'udp' }]);
});

test('filter: duplicate endpoints collapse and the list is capped', () => {
  const steps = [];
  for (let i = 0; i < 20; i += 1) steps.push({ url: `https://h${i}.dk/x` });
  steps.push({ url: 'https://h0.dk/y' });
  const targets = targetsForTest({ type: 'http', config: { steps } });
  assert.equal(targets.length, MAX_TARGETS);
});

test('filter: every address goes through net.isIP — nothing else may enter the expression', () => {
  for (const bad of ['notanip', '10.0.0.1 or host 1.2.3.4', '; rm -rf /', '-i', '10.0.0.999', '']) {
    const r = buildFilter([{ ip: bad, port: 443, proto: 'tcp' }]);
    assert.ok(r.error, `refused: ${JSON.stringify(bad)}`);
    assert.ok(!r.expression);
  }
});

test('filter: a bad port or protocol is refused, not defaulted', () => {
  assert.ok(buildFilter([{ ip: '10.0.0.1', port: 0, proto: 'tcp' }]).error);
  assert.ok(buildFilter([{ ip: '10.0.0.1', port: 70000, proto: 'tcp' }]).error);
  assert.ok(buildFilter([{ ip: '10.0.0.1', port: 443, proto: 'sctp' }]).error);
});

test('filter: no targets is a refusal, never a wider capture', () => {
  assert.match(buildFilter([]).error, /no capture targets/);
  assert.match(buildFilter(null).error, /no capture targets/);
});

test('filter: IPv6 icmp uses icmp6, which `icmp` would not match', () => {
  assert.equal(buildFilter([{ ip: '2001:db8::1', proto: 'icmp' }]).expression, '(icmp6 and host 2001:db8::1)');
  assert.equal(buildFilter([{ ip: '10.0.0.1', proto: 'icmp' }]).expression, '(icmp and host 10.0.0.1)');
});

test('filter: the argv is a list, and carries the fixed snaplen and packet cap', () => {
  const args = tcpdumpArgs({ iface: 'eth0', expression: '(host 10.0.0.1 and tcp port 443)', snaplen: 96, maxPackets: 2000 });
  assert.ok(Array.isArray(args));
  assert.deepEqual(args.slice(0, 9), ['-i', 'eth0', '-s', '96', '-w', '-', '-U', '-n', '-p']);
  assert.ok(args.includes('-c') && args.includes('2000'));
  assert.equal(args[args.length - 1], '(host 10.0.0.1 and tcp port 443)');
});

// ---------------------------------------------------------------- runner

test('capture: starts only once tcpdump is actually listening', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const startPromise = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => child.write(globalHeader()), 20);
  const out = await startPromise;
  assert.equal(out.ok, true);
  assert.equal(out.session.filter, '(host 10.0.0.2 and tcp port 443)');
  await out.session.stop({ keep: false });
});

test('capture: a run that passed keeps nothing at all', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => {
    child.write(globalHeader());
    child.write(packetRecord(tcpFrame()));
  }, 10);
  const { session } = await p;
  await new Promise((r) => setTimeout(r, 30));
  const result = await session.stop({ keep: false });
  assert.equal(result.kept, false);
  assert.deepEqual(result.packets, []);
});

test('capture: a run that failed keeps its packets', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => {
    child.write(globalHeader());
    child.write(packetRecord(tcpFrame({ flags: 0x02 })));
    child.write(packetRecord(tcpFrame({ flags: 0x04, sport: 443, dport: 51234, src: '10.0.0.2', dst: '10.0.0.1' })));
  }, 10);
  const { session } = await p;
  await new Promise((r) => setTimeout(r, 40));
  const result = await session.stop({ keep: true, observedPorts: [51234] });
  assert.equal(result.kept, true);
  assert.equal(result.packets.length, 2);
  assert.equal(result.packets[0].flags, 'S');
  assert.equal(result.packets[1].flags, 'R');
  assert.equal(result.foreign, 0);
});

test('capture: packets from another local conversation are discarded before they leave', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => {
    child.write(globalHeader());
    child.write(packetRecord(tcpFrame({ sport: 51234 })));  // ours
    child.write(packetRecord(tcpFrame({ sport: 40000 })));  // somebody else's, same far end
  }, 10);
  const { session } = await p;
  await new Promise((r) => setTimeout(r, 40));
  const result = await session.stop({ keep: true, observedPorts: [51234] });
  assert.equal(result.packets.length, 1);
  assert.equal(result.packets[0].sport, 51234);
  assert.equal(result.foreign, 1, 'and says how many it dropped');
});

test('capture: the packet ring is capped and says so', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0', maxPackets: 3 });
  setTimeout(() => {
    child.write(globalHeader());
    for (let i = 0; i < 10; i += 1) child.write(packetRecord(tcpFrame({ seq: i })));
  }, 10);
  const { session } = await p;
  await new Promise((r) => setTimeout(r, 40));
  const result = await session.stop({ keep: true });
  assert.equal(result.packets.length, 3);
  assert.equal(result.dropped, 7);
  assert.equal(result.truncated, true);
});

test('capture: one at a time', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => child.write(globalHeader()), 10);
  const first = await p;
  const second = await runner.start(HTTP_TEST, { iface: 'eth0' });
  assert.equal(second.ok, false);
  assert.match(second.reason, /already running/);
  await first.session.stop({ keep: false });
});

test('capture: a missing privilege is named, not reported as a generic failure', async () => {
  const child = fakeChild();
  const runner = runnerWith(child);
  const p = runner.start(HTTP_TEST, { iface: 'eth0' });
  setTimeout(() => {
    child.stderr.push("tcpdump: eth0: You don't have permission to capture on that device\n");
    child.emit('close', 1);
  }, 10);
  const out = await p;
  assert.equal(out.ok, false);
  assert.match(out.reason, /CAP_NET_RAW/);
});

test('capture: a test with no derivable target never starts tcpdump', async () => {
  let spawned = 0;
  const runner = createCaptureRunner({
    spawn: () => { spawned += 1; return fakeChild(); },
    platform: 'linux',
    lookup: (h, o, cb) => cb(null, '10.0.0.2'),
    readFile: async () => '',
    readProcNetRoute: async () => '',
  });
  const out = await runner.start({ id: 1, type: 'http', config: { steps: [] } }, {});
  assert.equal(out.ok, false);
  assert.match(out.reason, /no capture targets/);
  assert.equal(spawned, 0, 'nothing is spawned when there is nothing to capture');
});

test('capture: a target that will not resolve is a refusal, not a wider filter', async () => {
  const runner = createCaptureRunner({
    spawn: () => fakeChild(),
    platform: 'linux',
    lookup: (h, o, cb) => cb(new Error('ENOTFOUND')),
    readFile: async () => '',
    readProcNetRoute: async () => '',
  });
  const out = await runner.start(HTTP_TEST, {});
  assert.equal(out.ok, false);
  assert.match(out.reason, /could be resolved to an address/);
});

test('capture: non-Linux hosts decline with a reason', async () => {
  const runner = createCaptureRunner({ spawn: () => fakeChild(), platform: 'win32' });
  const out = await runner.start(HTTP_TEST, {});
  assert.equal(out.ok, false);
  assert.match(out.reason, /Linux-only/);
});

test('capture support: a missing tcpdump and a missing privilege read differently', async () => {
  const missing = await detectCaptureSupport({
    platform: 'linux',
    spawn: () => { const c = fakeChild(); setImmediate(() => c.emit('error', Object.assign(new Error('x'), { code: 'ENOENT' }))); return c; },
  });
  assert.equal(missing.available, false);
  assert.match(missing.reason, /not installed/);

  const denied = await detectCaptureSupport({
    platform: 'linux',
    spawn: () => {
      const c = fakeChild();
      setImmediate(() => { c.stderr.push('tcpdump: no permission to open device\n'); c.emit('close', 1); });
      return c;
    },
  });
  assert.equal(denied.available, false);
  assert.match(denied.reason, /CAP_NET_RAW/);
});

test('observedPortsOf: reads the local ports out of the phase records', () => {
  assert.deepEqual(observedPortsOf({ step_phases: [{ localPort: 51234 }, { localPort: 51235 }, { localPort: 51234 }, null] }), [51234, 51235]);
  assert.deepEqual(observedPortsOf({}), []);
});
