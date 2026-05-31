'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseTemplated } = require('../src/netflow/parseTemplated');
const { createNetflowCollector } = require('../src/netflow/collector');

// Field IDs we use (shared by v9 and IPFIX).
const F = { IN_BYTES: 1, IN_PKTS: 2, PROTOCOL: 4, SRC_PORT: 7, SRC_ADDR: 8, DST_PORT: 11, DST_ADDR: 12 };

// A template: dst/src addr (4), src/dst port (2), protocol (1), bytes (4), pkts (4).
const TEMPLATE = [
  { type: F.SRC_ADDR, length: 4 },
  { type: F.DST_ADDR, length: 4 },
  { type: F.SRC_PORT, length: 2 },
  { type: F.DST_PORT, length: 2 },
  { type: F.PROTOCOL, length: 1 },
  { type: F.IN_BYTES, length: 4 },
  { type: F.IN_PKTS, length: 4 },
];
const RECORD_LEN = TEMPLATE.reduce((s, f) => s + f.length, 0); // 21

function header(version, count, sourceId) {
  if (version === 9) {
    const h = Buffer.alloc(20);
    h.writeUInt16BE(9, 0); h.writeUInt16BE(count, 2);
    h.writeUInt32BE(1000, 4); h.writeUInt32BE(1780000000, 8);
    h.writeUInt32BE(1, 12); h.writeUInt32BE(sourceId, 16);
    return h;
  }
  const h = Buffer.alloc(16); // IPFIX
  h.writeUInt16BE(10, 0); // length filled by caller-agnostic parser (not checked)
  h.writeUInt32BE(1780000000, 4); h.writeUInt32BE(1, 8); h.writeUInt32BE(sourceId, 12);
  return h;
}

function templateSet(version, templateId) {
  const TEMPLATE_SETID = version === 9 ? 0 : 2;
  const body = Buffer.alloc(4 + TEMPLATE.length * 4);
  body.writeUInt16BE(templateId, 0);
  body.writeUInt16BE(TEMPLATE.length, 2);
  TEMPLATE.forEach((f, i) => {
    body.writeUInt16BE(f.type, 4 + i * 4);
    body.writeUInt16BE(f.length, 6 + i * 4);
  });
  const set = Buffer.alloc(4 + body.length);
  set.writeUInt16BE(TEMPLATE_SETID, 0);
  set.writeUInt16BE(set.length, 2);
  body.copy(set, 4);
  return set;
}

function dataSet(templateId, flows) {
  const body = Buffer.alloc(flows.length * RECORD_LEN);
  flows.forEach((f, i) => {
    let o = i * RECORD_LEN;
    f.src.split('.').forEach((b, j) => (body[o + j] = Number(b))); o += 4;
    f.dst.split('.').forEach((b, j) => (body[o + j] = Number(b))); o += 4;
    body.writeUInt16BE(f.srcPort, o); o += 2;
    body.writeUInt16BE(f.dstPort, o); o += 2;
    body[o] = f.protocol; o += 1;
    body.writeUInt32BE(f.bytes, o); o += 4;
    body.writeUInt32BE(f.packets, o); o += 4;
  });
  const set = Buffer.alloc(4 + body.length);
  set.writeUInt16BE(templateId, 0);
  set.writeUInt16BE(set.length, 2);
  body.copy(set, 4);
  return set;
}

const FLOWS = [
  { src: '10.0.0.5', dst: '93.184.216.34', srcPort: 50000, dstPort: 443, protocol: 6, bytes: 1500, packets: 10 },
  { src: '10.0.0.5', dst: '8.8.8.8', srcPort: 51000, dstPort: 53, protocol: 17, bytes: 200, packets: 2 },
];

for (const version of [9, 10]) {
  const label = version === 9 ? 'v9' : 'IPFIX';

  test(`parseTemplated (${label}) decodes data when template is in the same packet`, () => {
    const pkt = Buffer.concat([header(version, 3, 7), templateSet(version, 256), dataSet(256, FLOWS)]);
    const { flows, templatesLearned } = parseTemplated(pkt, new Map());
    assert.equal(templatesLearned, 1);
    assert.equal(flows.length, 2);
    assert.equal(flows[0].dstAddr, '93.184.216.34');
    assert.equal(flows[0].dstPort, 443);
    assert.equal(flows[0].protocolName, 'tcp');
    assert.equal(flows[0].bytes, 1500);
    assert.equal(flows[1].protocolName, 'udp');
    assert.equal(flows[1].dstPort, 53);
  });

  test(`parseTemplated (${label}) caches templates across packets`, () => {
    const templates = new Map();
    // Packet 1: only the template -> no flows yet.
    const p1 = Buffer.concat([header(version, 1, 7), templateSet(version, 300)]);
    const r1 = parseTemplated(p1, templates);
    assert.equal(r1.flows.length, 0);
    assert.equal(r1.templatesLearned, 1);

    // Packet 2: only data, relying on the cached template.
    const p2 = Buffer.concat([header(version, 2, 7), dataSet(300, FLOWS)]);
    const r2 = parseTemplated(p2, templates);
    assert.equal(r2.flows.length, 2);
    assert.equal(r2.flows[0].dstPort, 443);
  });

  test(`parseTemplated (${label}) skips data with an unknown template`, () => {
    const pkt = Buffer.concat([header(version, 1, 7), dataSet(999, FLOWS)]);
    const r = parseTemplated(pkt, new Map());
    assert.equal(r.flows.length, 0);
    assert.equal(r.skippedNoTemplate, 1);
  });
}

test('parseTemplated rejects an unexpected version', () => {
  const bad = Buffer.alloc(16); bad.writeUInt16BE(7, 0);
  assert.throws(() => parseTemplated(bad, new Map()));
});

test('collector decodes v9 packets (version dispatch) and keeps templates', () => {
  const c = createNetflowCollector();
  c._feed(Buffer.concat([header(9, 1, 7), templateSet(9, 256)])); // template only
  assert.equal(c.bufferedFlows, 0);
  c._feed(Buffer.concat([header(9, 2, 7), dataSet(256, FLOWS)])); // data uses cached template
  assert.equal(c.bufferedFlows, 2);
  const snap = c.drain();
  assert.equal(snap.totals.bytes, 1700);
  const p443 = snap.byPort.find((p) => p.port === 443);
  assert.equal(p443.bytes, 1500);
});
