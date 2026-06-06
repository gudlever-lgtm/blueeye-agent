'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { decodeSampledHeader } = require('../src/sflow/decodePacket');
const { parseSflow } = require('../src/sflow/parse');
const { createSflowCollector } = require('../src/sflow/collector');

// Builds an Ethernet II + IPv4 + TCP/UDP raw header for a sampled packet.
function rawPacket({ src, dst, srcPort, dstPort, protocol }) {
  const eth = Buffer.alloc(14);
  eth.writeUInt16BE(0x0800, 12); // IPv4
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; // version 4, IHL 5
  ip[9] = protocol;
  src.split('.').forEach((b, i) => (ip[12 + i] = Number(b)));
  dst.split('.').forEach((b, i) => (ip[16 + i] = Number(b)));
  const l4 = Buffer.alloc(4);
  l4.writeUInt16BE(srcPort, 0);
  l4.writeUInt16BE(dstPort, 2);
  return Buffer.concat([eth, ip, l4]);
}

// Builds an sFlow v5 datagram with one flow sample carrying one raw-packet-header
// record, for the given sampling rate and frame length.
function sflowDatagram({ samplingRate, frameLength, raw }) {
  // raw packet header record (type 1): header_protocol, frame_length, stripped,
  // header_length, header[]
  const recHeader = Buffer.alloc(16);
  recHeader.writeUInt32BE(1, 0); // header_protocol = ethernet
  recHeader.writeUInt32BE(frameLength, 4);
  recHeader.writeUInt32BE(0, 8); // stripped
  recHeader.writeUInt32BE(raw.length, 12);
  const recBody = Buffer.concat([recHeader, raw]);
  const rec = Buffer.concat([be(1), be(recBody.length), recBody]); // recType=1

  // flow sample body (type 1): seq, sourceId, samplingRate, samplePool, drops,
  // input, output, numRecords, records...
  const sampleBody = Buffer.concat([
    be(1), // sequence
    be(0), // source id
    be(samplingRate),
    be(0), // sample pool
    be(0), // drops
    be(0), // input if
    be(0), // output if
    be(1), // num records
    rec,
  ]);
  const sample = Buffer.concat([be(1), be(sampleBody.length), sampleBody]); // sampleType=1

  // datagram header: version, ipVersion, agentAddr(4), subAgent, seq, uptime,
  // numSamples
  const head = Buffer.concat([
    be(5), be(1), Buffer.from([10, 0, 0, 1]), be(0), be(1), be(1000), be(1),
  ]);
  return Buffer.concat([head, sample]);
}

function be(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; }

const TCP = { src: '10.0.0.5', dst: '93.184.216.34', srcPort: 50000, dstPort: 443, protocol: 6 };

test('decodeSampledHeader extracts the 5-tuple from Ethernet+IPv4+TCP', () => {
  const flow = decodeSampledHeader(rawPacket(TCP), 1500);
  assert.equal(flow.srcAddr, '10.0.0.5');
  assert.equal(flow.dstAddr, '93.184.216.34');
  assert.equal(flow.dstPort, 443);
  assert.equal(flow.protocolName, 'tcp');
  assert.equal(flow.bytes, 1500); // uses the reported frame length
});

test('decodeSampledHeader returns null for non-IP frames', () => {
  const eth = Buffer.alloc(40);
  eth.writeUInt16BE(0x0806, 12); // ARP
  assert.equal(decodeSampledHeader(eth, 60), null);
});

test('parseSflow decodes a flow sample and scales bytes by the sampling rate', () => {
  const dg = sflowDatagram({ samplingRate: 1000, frameLength: 1500, raw: rawPacket(TCP) });
  const { header, flows } = parseSflow(dg);
  assert.equal(header.version, 5);
  assert.equal(flows.length, 1);
  assert.equal(flows[0].dstPort, 443);
  assert.equal(flows[0].protocolName, 'tcp');
  assert.equal(flows[0].bytes, 1500 * 1000); // rate-scaled
  assert.equal(flows[0].packets, 1000);
  assert.equal(flows[0].sampled, true);
});

test('parseSflow rejects an unsupported version', () => {
  const bad = Buffer.alloc(28); bad.writeUInt32BE(4, 0);
  assert.throws(() => parseSflow(bad));
});

test('sFlow collector buffers and drains an aggregated snapshot', () => {
  const c = createSflowCollector();
  c._feed(sflowDatagram({ samplingRate: 100, frameLength: 1000, raw: rawPacket(TCP) }));
  c._feed(sflowDatagram({ samplingRate: 100, frameLength: 1000,
    raw: rawPacket({ src: '10.0.0.6', dst: '8.8.8.8', srcPort: 51000, dstPort: 53, protocol: 17 }) }));
  assert.equal(c.bufferedFlows, 2);

  const snap = c.drain();
  assert.equal(snap.source, 'sflow');
  assert.equal(snap.sampled, true);
  assert.equal(snap.totals.bytes, 1000 * 100 + 1000 * 100);
  const p443 = snap.byPort.find((p) => p.port === 443);
  assert.equal(p443.bytes, 100000);
  const udp = snap.byProtocol.find((p) => p.protocol === 'udp');
  assert.equal(udp.bytes, 100000);

  // A malformed datagram is dropped, not thrown.
  c._feed(Buffer.from([0, 0, 0, 4]));
  assert.equal(c.drain().droppedDatagrams, 1);
});

test('sFlow collector stats() reports receive/decode counters without draining', () => {
  const c = createSflowCollector();
  // Before any traffic: not bound, nothing seen.
  let s = c.stats();
  assert.equal(s.listening, false);
  assert.equal(s.datagrams, 0);
  assert.equal(s.decodedFlows, 0);
  assert.equal(s.lastDatagramAt, null);

  c._feed(sflowDatagram({ samplingRate: 100, frameLength: 1000, raw: rawPacket(TCP) }));
  c._feed(Buffer.from([0, 0, 0, 4])); // malformed -> dropped, still "seen"

  s = c.stats();
  assert.equal(s.datagrams, 1); // one parsed
  assert.equal(s.dropped, 1); // one malformed
  assert.equal(s.decodedFlows, 1); // one flow record decoded
  assert.equal(s.bufferedFlows, 1); // not yet drained
  assert.equal(typeof s.lastDatagramAt, 'string');

  // stats() must NOT clear the buffer — a following drain still sees the flow.
  assert.equal(c.drain().byPort.length, 1);
  // Cumulative counters survive the drain; the buffer resets.
  assert.equal(c.stats().decodedFlows, 1);
  assert.equal(c.stats().bufferedFlows, 0);
});
