'use strict';

// sFlow enrichment: counter samples (generic + Ethernet interface counters)
// decoded and forwarded as `sflowCounters`, and flow samples keeping their
// in/out ifIndex, 802.1Q VLAN and MAC addresses. NetFlow v9/IPFIX gets the same
// VLAN/interface fields from IEs 10/14/58/243.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseSflow, ETHERNET_FIELDS } = require('../src/sflow/parse');
const { decodeSampledHeader } = require('../src/sflow/decodePacket');
const {
  createSflowCollector, IF_COUNTER_FIELDS, RESULT_BUDGET_BYTES,
} = require('../src/sflow/collector');
const { aggregateFlows } = require('../src/netflow/aggregate');
const { applyField, finaliseFlow, FIELD } = require('../src/netflow/fields');

const be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n), 0); return b; };
const ALL1_32 = 0xffffffff;

function datagram(samples, { agent = [10, 14, 0, 2], uptime = 123456 } = {}) {
  const v6 = agent.length === 16;
  const head = Buffer.concat([
    be(5), be(v6 ? 2 : 1), Buffer.from(agent), be(0), be(1), be(uptime), be(samples.length),
  ]);
  return Buffer.concat([head, ...samples]);
}

function record(type, body) { return Buffer.concat([be(type), be(body.length), body]); }

function genericIf(over = {}) {
  const c = {
    ifIndex: 7, ifType: 6, ifSpeed: 1e9, ifDirection: 2, ifStatus: 3,
    ifInOctets: 5e10, ifInUcastPkts: 1000, ifInMulticastPkts: 10, ifInBroadcastPkts: 20,
    ifInDiscards: 1, ifInErrors: 2, ifInUnknownProtos: ALL1_32, ifOutOctets: 6e10,
    ifOutUcastPkts: 2000, ifOutMulticastPkts: 30, ifOutBroadcastPkts: 40, ifOutDiscards: 3,
    ifOutErrors: 4, ifPromiscuousMode: 0, ...over,
  };
  return record(1, Buffer.concat([
    be(c.ifIndex), be(c.ifType), be64(c.ifSpeed), be(c.ifDirection), be(c.ifStatus),
    be64(c.ifInOctets), be(c.ifInUcastPkts), be(c.ifInMulticastPkts), be(c.ifInBroadcastPkts),
    be(c.ifInDiscards), be(c.ifInErrors), be(c.ifInUnknownProtos), be64(c.ifOutOctets),
    be(c.ifOutUcastPkts), be(c.ifOutMulticastPkts), be(c.ifOutBroadcastPkts), be(c.ifOutDiscards),
    be(c.ifOutErrors), be(c.ifPromiscuousMode),
  ]));
}

function ethernet(values = {}) {
  return record(2, Buffer.concat(ETHERNET_FIELDS.map((f, i) => be(values[f] ?? i))));
}

function counterSample(records, { expanded = false, ifIndex = 7 } = {}) {
  const src = expanded ? Buffer.concat([be(0), be(ifIndex)]) : be(ifIndex);
  const body = Buffer.concat([be(1), src, be(records.length), ...records]);
  return Buffer.concat([be(expanded ? 4 : 2), be(body.length), body]);
}

// Ethernet (+ optional 802.1Q tag) + IPv4 + TCP.
function frame({ vlan = null } = {}) {
  const dst = Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
  const src = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  const tag = vlan == null ? Buffer.alloc(0) : Buffer.concat([Buffer.from([0x81, 0x00]), Buffer.from([(vlan >> 8) & 0x0f, vlan & 0xff])]);
  const type = Buffer.from([0x08, 0x00]);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip[9] = 6;
  [10, 0, 0, 5].forEach((b, i) => { ip[12 + i] = b; });
  [10, 0, 1, 9].forEach((b, i) => { ip[16 + i] = b; });
  const l4 = Buffer.alloc(4);
  l4.writeUInt16BE(50000, 0); l4.writeUInt16BE(502, 2);
  return Buffer.concat([dst, src, tag, type, ip, l4]);
}

function flowSample({ vlan = null, inIf = 3, outIf = 9, expanded = false, switchVlan = null } = {}) {
  const raw = frame({ vlan });
  const hdr = Buffer.concat([be(1), be(1500), be(0), be(raw.length), raw]);
  const records = [record(1, hdr)];
  if (switchVlan != null) records.push(record(1001, Buffer.concat([be(switchVlan), be(0), be(switchVlan), be(0)])));
  const ifs = expanded
    ? Buffer.concat([be(0), be(inIf), be(0), be(outIf)])
    : Buffer.concat([be(inIf), be(outIf)]);
  const body = Buffer.concat([
    be(1), expanded ? Buffer.concat([be(0), be(3)]) : be(3), be(100), be(0), be(0), ifs, be(records.length), ...records,
  ]);
  return Buffer.concat([be(expanded ? 3 : 1), be(body.length), body]);
}

// ---------------------------------------------------------------- parsing
test('a counter sample decodes the generic and Ethernet records; all-ones is null', () => {
  const p = parseSflow(datagram([counterSample([genericIf(), ethernet({ dot3StatsLateCollisions: 17 })])]));
  assert.equal(p.counterSamples, 1);
  assert.equal(p.header.agent, '10.14.0.2');
  assert.equal(p.counters.length, 1);
  const c = p.counters[0];
  assert.equal(c.agent, '10.14.0.2');
  assert.equal(c.ifIndex, 7);
  assert.equal(c.uptimeMs, 123456);
  assert.equal(c.generic.ifSpeed, 1e9);
  assert.equal(c.generic.ifDirection, 2, 'half duplex');
  assert.equal(c.generic.ifStatus, 3, 'admin + oper up');
  assert.equal(c.generic.ifInOctets, 5e10, '64-bit counters survive past 2^32');
  assert.equal(c.generic.ifInUnknownProtos, null, 'all-ones = not available, not 4294967295');
  assert.equal(c.ethernet.dot3StatsLateCollisions, 17);
  assert.equal(c.ethernet.dot3StatsAlignmentErrors, 0);
});

test('an expanded counter sample and an IPv6 exporter address (compressed form)', () => {
  const agent = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
  const p = parseSflow(datagram([counterSample([genericIf({ ifIndex: 1001 })], { expanded: true, ifIndex: 1001 })], { agent }));
  assert.equal(p.counters[0].agent, '2001:db8::1');
  assert.equal(p.counters[0].ifIndex, 1001);
  assert.equal(p.counters[0].ethernet, null);
});

test('an Ethernet-only counter sample takes its ifIndex from the source id', () => {
  const p = parseSflow(datagram([counterSample([ethernet()], { ifIndex: 12 })]));
  assert.equal(p.counters[0].ifIndex, 12);
  assert.equal(p.counters[0].generic, null);
});

test('a counter sample with no record we read is counted, not decoded', () => {
  const p = parseSflow(datagram([counterSample([record(1005, Buffer.alloc(8))])]));
  assert.equal(p.counterSamples, 1);
  assert.deepEqual(p.counters, []);
});

test('a truncated counter record is skipped, not read past its end', () => {
  const good = genericIf();
  const cut = Buffer.concat([be(1), be(88), good.subarray(8, 40)]); // claims 88, has 32
  const body = Buffer.concat([be(1), be(7), be(1), cut]);
  const sample = Buffer.concat([be(2), be(body.length), body]);
  const p = parseSflow(datagram([sample]));
  assert.deepEqual(p.counters, []);
});

test('a flow sample keeps in/out ifIndex, the 802.1Q VLAN and the MACs', () => {
  const p = parseSflow(datagram([flowSample({ vlan: 120 })]));
  const f = p.flows[0];
  assert.equal(f.inIf, 3);
  assert.equal(f.outIf, 9);
  assert.equal(f.vlan, 120);
  assert.equal(f.srcMac, 'aa:bb:cc:dd:ee:ff');
  assert.equal(f.dstMac, '00:11:22:33:44:55');
  assert.equal(f.dstPort, 502, 'the 5-tuple is still read behind the tag');
  assert.equal(f.bytes, 1500 * 100);
});

test('expanded flow samples read the format+value interface words', () => {
  const f = parseSflow(datagram([flowSample({ expanded: true, inIf: 70000, outIf: 70001 })])).flows[0];
  assert.equal(f.inIf, 70000);
  assert.equal(f.outIf, 70001);
});

test('unknown / non-ifIndex interface words are null, not a port', () => {
  // 0x3FFFFFFF = unknown; format 1 (top bits 01) = a discard reason; format 2 = multiple ports.
  const f = parseSflow(datagram([flowSample({ inIf: 0x3fffffff, outIf: 0x80000003 })])).flows[0];
  assert.equal(f.inIf, undefined);
  assert.equal(f.outIf, undefined);
});

test('an untagged frame takes its VLAN from the extended switch record', () => {
  const f = parseSflow(datagram([flowSample({ switchVlan: 30 })])).flows[0];
  assert.equal(f.vlan, 30);
  const tagged = parseSflow(datagram([flowSample({ vlan: 120, switchVlan: 30 })])).flows[0];
  assert.equal(tagged.vlan, 120, 'the tag in the frame wins');
});

test('decodeSampledHeader: a priority-only tag (VID 0) is not a VLAN', () => {
  const f = decodeSampledHeader(frame({ vlan: 0 }), 100);
  assert.equal(f.vlan, undefined);
  assert.equal(f.dstPort, 502);
});

// ---------------------------------------------------------------- aggregate
test('aggregated flows carry vlan / inIf / outIf, and the VLAN splits the key', () => {
  const base = { srcAddr: '10.0.0.5', dstAddr: '10.0.1.9', srcPort: 50000, dstPort: 502, protocolName: 'tcp', bytes: 100, packets: 1 };
  const agg = aggregateFlows([
    { ...base, vlan: 10, inIf: 3, outIf: 9 },
    { ...base, vlan: 10, inIf: 4 }, // same conversation, second port: first one kept
    { ...base, vlan: 20 },
    { ...base }, // NetFlow v5 shape: no L2 fields at all
  ]);
  const byVlan = new Map(agg.flows.map((f) => [f.vlan ?? null, f]));
  assert.equal(agg.flows.length, 3);
  assert.deepEqual(
    { vlan: byVlan.get(10).vlan, inIf: byVlan.get(10).inIf, outIf: byVlan.get(10).outIf, flows: byVlan.get(10).flows },
    { vlan: 10, inIf: 3, outIf: 9, flows: 2 },
  );
  assert.equal(byVlan.get(20).inIf, undefined);
  assert.equal('vlan' in byVlan.get(null), false, 'no key at all when the exporter did not say');
});

test('NetFlow v9/IPFIX: IE 10/14 are the interfaces, 58/243 the VLAN (243 wins)', () => {
  const flow = {};
  const b = Buffer.alloc(4);
  const put = (type, v, len = 4) => { b.writeUIntBE(v, 0, len); applyField(flow, type, b, 0, len); };
  put(FIELD.INPUT_SNMP, 5);
  put(FIELD.OUTPUT_SNMP, 6, 2);
  put(FIELD.DOT1Q_VLAN, 300, 2);
  put(FIELD.SRC_VLAN, 400, 2);
  const out = finaliseFlow(flow);
  assert.equal(out.inIf, 5);
  assert.equal(out.outIf, 6);
  assert.equal(out.vlan, 300);
  const none = finaliseFlow({});
  assert.equal('vlan' in none || 'inIf' in none || 'outIf' in none, false);
});

// ---------------------------------------------------------------- collector
test('the collector forwards the latest reading per (exporter, ifIndex) as sflowCounters', () => {
  let t = 1_000_000;
  const col = createSflowCollector({ now: () => t });
  col._feed(datagram([counterSample([genericIf({ ifInOctets: 100 }), ethernet()])]));
  t += 20000;
  col._feed(datagram([counterSample([genericIf({ ifInOctets: 200 }), ethernet({ dot3StatsLateCollisions: 5 })])]));
  col._feed(datagram([counterSample([genericIf({ ifIndex: 8 })], { ifIndex: 8 })]));
  const snap = col.drain();
  assert.equal(snap.sflowCounters.length, 2);
  const e = snap.sflowCounters.find((x) => x.ifIndex === 7);
  assert.equal(e.agent, '10.14.0.2');
  assert.equal(e.at, t);
  assert.equal(e.if[IF_COUNTER_FIELDS.indexOf('ifInOctets')], 200, 'the latest reading');
  assert.equal(e.if[IF_COUNTER_FIELDS.indexOf('ifInUnknownProtos')], null);
  assert.equal(e.eth[ETHERNET_FIELDS.indexOf('dot3StatsLateCollisions')], 5);
  assert.equal(e.direction, 2);
  assert.equal(e.speed, 1e9);
  assert.equal(snap.sflowCounters.find((x) => x.ifIndex === 8).eth, undefined);
  assert.equal(col.drain().sflowCounters, undefined, 'sent once; nothing new, no key');
  assert.equal(col.stats().counterSamples, 3);
});

test('more interfaces than fit ROTATE across snapshots — none starved, none twice', () => {
  let t = 1_000_000;
  const col = createSflowCollector({ now: () => t });
  for (let i = 1; i <= 400; i += 1) col._feed(datagram([counterSample([genericIf({ ifIndex: i }), ethernet()], { ifIndex: i })]));
  const seen = new Set();
  let rounds = 0;
  while (rounds < 10) {
    rounds += 1;
    t += 60000;
    const snap = col.drain();
    assert.ok(Buffer.byteLength(JSON.stringify(snap)) < RESULT_BUDGET_BYTES, 'the snapshot stays under the result budget');
    if (!snap.sflowCounters) break;
    for (const c of snap.sflowCounters) {
      assert.equal(seen.has(c.ifIndex), false, `ifIndex ${c.ifIndex} sent twice`);
      seen.add(c.ifIndex);
    }
  }
  assert.equal(seen.size, 400);
  assert.ok(rounds > 2, 'it did not all fit in one snapshot');
});

test('a reading older than ten minutes is dropped rather than sent', () => {
  let t = 1_000_000;
  const col = createSflowCollector({ now: () => t });
  col._feed(datagram([counterSample([genericIf()])]));
  t += 11 * 60 * 1000;
  assert.equal(col.drain().sflowCounters, undefined);
});
