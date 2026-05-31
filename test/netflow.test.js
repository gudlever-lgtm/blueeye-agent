'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseV5, HEADER_BYTES, RECORD_BYTES } = require('../src/netflow/parseV5');
const { aggregateFlows, servicePort } = require('../src/netflow/aggregate');
const { createNetflowCollector } = require('../src/netflow/collector');

// Builds a NetFlow v5 packet from simple flow specs for testing.
function buildV5(flows) {
  const buf = Buffer.alloc(HEADER_BYTES + flows.length * RECORD_BYTES);
  buf.writeUInt16BE(5, 0); // version
  buf.writeUInt16BE(flows.length, 2); // count
  buf.writeUInt32BE(123456, 4); // sysUptime
  buf.writeUInt32BE(1780000000, 8); // unixSecs
  flows.forEach((f, i) => {
    const o = HEADER_BYTES + i * RECORD_BYTES;
    const [a, b, c, d] = f.src.split('.').map(Number);
    buf[o] = a; buf[o + 1] = b; buf[o + 2] = c; buf[o + 3] = d;
    const [e, g, h, k] = f.dst.split('.').map(Number);
    buf[o + 4] = e; buf[o + 5] = g; buf[o + 6] = h; buf[o + 7] = k;
    buf.writeUInt32BE(f.packets, o + 16);
    buf.writeUInt32BE(f.bytes, o + 20);
    buf.writeUInt16BE(f.srcPort, o + 32);
    buf.writeUInt16BE(f.dstPort, o + 34);
    buf[o + 38] = f.protocol;
  });
  return buf;
}

const SAMPLE = [
  { src: '10.0.0.5', dst: '93.184.216.34', srcPort: 50000, dstPort: 443, protocol: 6, packets: 10, bytes: 1500 },
  { src: '10.0.0.6', dst: '93.184.216.34', srcPort: 50001, dstPort: 443, protocol: 6, packets: 5, bytes: 800 },
  { src: '10.0.0.5', dst: '8.8.8.8', srcPort: 51000, dstPort: 53, protocol: 17, packets: 2, bytes: 200 },
];

test('parseV5 decodes header and flow records', () => {
  const { header, flows } = parseV5(buildV5(SAMPLE));
  assert.equal(header.version, 5);
  assert.equal(header.count, 3);
  assert.equal(flows.length, 3);
  assert.equal(flows[0].dstAddr, '93.184.216.34');
  assert.equal(flows[0].dstPort, 443);
  assert.equal(flows[0].protocolName, 'tcp');
  assert.equal(flows[2].protocolName, 'udp');
  assert.equal(flows[2].dstPort, 53);
});

test('parseV5 rejects a malformed packet', () => {
  assert.throws(() => parseV5(Buffer.alloc(4)));
  const wrongVersion = buildV5([]); wrongVersion.writeUInt16BE(9, 0);
  assert.throws(() => parseV5(wrongVersion));
});

test('servicePort picks the lower (server) port', () => {
  assert.equal(servicePort({ srcPort: 50000, dstPort: 443 }), 443);
  assert.equal(servicePort({ srcPort: 53, dstPort: 51000 }), 53);
});

test('aggregateFlows summarises by port and protocol', () => {
  const { flows } = parseV5(buildV5(SAMPLE));
  const agg = aggregateFlows(flows);

  assert.equal(agg.totals.bytes, 2500);
  assert.equal(agg.totals.flows, 3);

  const p443 = agg.byPort.find((p) => p.port === 443);
  assert.equal(p443.bytes, 2300); // 1500 + 800
  assert.equal(p443.flows, 2);

  const tcp = agg.byProtocol.find((p) => p.protocol === 'tcp');
  assert.equal(tcp.bytes, 2300);
  const udp = agg.byProtocol.find((p) => p.protocol === 'udp');
  assert.equal(udp.bytes, 200);

  // Sorted by bytes desc — 443 is the top port.
  assert.equal(agg.byPort[0].port, 443);
});

test('collector buffers fed packets and drains an aggregated snapshot', () => {
  const c = createNetflowCollector();
  c._feed(buildV5(SAMPLE));
  c._feed(buildV5([{ src: '10.0.0.9', dst: '1.1.1.1', srcPort: 52000, dstPort: 443, protocol: 6, packets: 1, bytes: 700 }]));
  assert.equal(c.bufferedFlows, 4);

  const snap = c.drain();
  assert.equal(snap.source, 'netflow');
  assert.equal(snap.packets, 2);
  assert.equal(snap.totals.bytes, 3200); // 2500 + 700
  assert.equal(c.bufferedFlows, 0); // drained

  // A bad packet is dropped, not thrown.
  c._feed(Buffer.from([0, 9, 0, 0]));
  const snap2 = c.drain();
  assert.equal(snap2.droppedPackets, 1);
  assert.equal(snap2.totals.flows, 0);
});

test('collector caps buffered flows at maxFlows', () => {
  const c = createNetflowCollector({ maxFlows: 2 });
  c._feed(buildV5(SAMPLE)); // 3 flows, but capped at 2
  assert.equal(c.bufferedFlows, 2);
});
