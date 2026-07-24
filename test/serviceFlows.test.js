'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { aggregateFlows } = require('../src/netflow/aggregate');
const { collectLocalIps } = require('../src/localIps');

const FLOWS = [
  { srcAddr: '10.0.0.5', dstAddr: '10.0.0.9', srcPort: 51000, dstPort: 443, protocolName: 'tcp', bytes: 1000, packets: 8 },
  { srcAddr: '10.0.0.5', dstAddr: '10.0.0.9', srcPort: 51002, dstPort: 443, protocolName: 'tcp', bytes: 500, packets: 4 },
  { srcAddr: '10.0.0.5', dstAddr: '10.0.0.9', srcPort: 51004, dstPort: 5432, protocolName: 'tcp', bytes: 200, packets: 2 },
  { srcAddr: '10.0.0.7', dstAddr: '8.8.8.8', srcPort: 40000, dstPort: 53, protocolName: 'udp', bytes: 90, packets: 1 },
];

test('aggregateFlows emits a per-5-tuple flows list keyed by (src,dst,dstPort,proto)', () => {
  const agg = aggregateFlows(FLOWS);
  assert.ok(Array.isArray(agg.flows), 'flows list is present');

  // The two :443 flows between the same pair collapse into one edge; the :5432
  // flow stays separate even though the pair is identical.
  const https = agg.flows.find((f) => f.dstIp === '10.0.0.9' && f.dstPort === 443);
  assert.equal(https.bytes, 1500); // 1000 + 500
  assert.equal(https.packets, 12);
  assert.equal(https.flows, 2);
  assert.equal(https.proto, 'tcp');
  assert.equal(https.srcIp, '10.0.0.5');

  const pg = agg.flows.find((f) => f.dstIp === '10.0.0.9' && f.dstPort === 5432);
  assert.equal(pg.bytes, 200);
  assert.equal(pg.flows, 1);

  // Distinct (src,dst,dstPort,proto) tuples: 443, 5432, 53 -> 3 edges.
  assert.equal(agg.flows.length, 3);
  // Sorted by bytes desc.
  assert.equal(agg.flows[0].dstPort, 443);
});

test('aggregateFlows keeps topTalkers/byPort untouched (backward compatible)', () => {
  const agg = aggregateFlows(FLOWS);
  assert.ok(Array.isArray(agg.topTalkers) && agg.topTalkers.length);
  assert.ok(Array.isArray(agg.byPort) && agg.byPort.length);
  assert.ok(Array.isArray(agg.byProtocol) && agg.byProtocol.length);
});

test('aggregateFlows caps the flows list at flowTopN by bytes', () => {
  const many = [];
  for (let i = 0; i < 10; i += 1) {
    many.push({ srcAddr: `10.0.0.${i}`, dstAddr: '10.0.0.99', srcPort: 5000 + i, dstPort: 443, protocolName: 'tcp', bytes: (i + 1) * 100, packets: 1 });
  }
  const agg = aggregateFlows(many, { flowTopN: 3 });
  assert.equal(agg.flows.length, 3);
  // The three heaviest survive (900, 1000 come from i=8,9...).
  assert.equal(agg.flows[0].bytes, 1000);
});

test('collectLocalIps returns non-internal, non-link-local addresses', () => {
  const ips = collectLocalIps({
    networkInterfaces: () => ({
      lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
      eth0: [
        { address: '10.0.0.5', family: 'IPv4', internal: false },
        { address: 'fe80::1', family: 'IPv6', internal: false },
        { address: '169.254.1.1', family: 'IPv4', internal: false },
        { address: '2001:db8::1', family: 'IPv6', internal: false },
      ],
    }),
  });
  assert.deepEqual(ips.sort(), ['10.0.0.5', '2001:db8::1'].sort());
});

test('collectLocalIps is resilient to a throwing provider', () => {
  const ips = collectLocalIps({ networkInterfaces: () => { throw new Error('nope'); } });
  assert.deepEqual(ips, []);
});
