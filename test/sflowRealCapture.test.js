'use strict';

// Real sFlow v5 datagrams, captured from hsflowd 2.1.26 sampling a veth pair
// (see test/fixtures/sflow/README.md). test/sflow.test.js builds its datagrams
// by hand, in the compact sample formats; hsflowd sends the EXPANDED ones
// (types 3/4) and puts extended records next to the raw header, so this is the
// check that the parser reads what an exporter actually emits.
//
// The expectations come from an independent walk of the XDR below (a few
// lines, written from sFlow v5 §5, not from src/sflow/parse.js), so a bug in
// the parser cannot agree with itself.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const dgram = require('dgram');
const net = require('net');

const { parseSflow } = require('../src/sflow/parse');
const { aggregateFlows } = require('../src/netflow/aggregate');
const { createSflowCollector } = require('../src/sflow/collector');

const DIR = path.join(__dirname, 'fixtures', 'sflow');
const FILES = fs.readdirSync(DIR).filter((f) => /^hsflowd-.*\.bin$/.test(f)).sort();
const load = (f) => fs.readFileSync(path.join(DIR, f));

const AGENT = '192.0.2.2';
const HOSTS = new Set(['198.51.100.1', '198.51.100.2']);
const SAMPLING_RATE = 8;

// Independent XDR walk: datagram header + per-sample type, and for each flow
// sample its sampling rate and the raw-header record's frame length.
function walk(buf) {
  let o = 0;
  const u32 = () => { const v = buf.readUInt32BE(o); o += 4; return v; };
  const version = u32();
  const addrType = u32();
  const agent = addrType === 1 ? [...buf.subarray(o, o + 4)].join('.') : null;
  o += addrType === 1 ? 4 : 16;
  const subAgent = u32();
  const sequence = u32();
  u32(); // uptime
  const n = u32();
  const samples = [];
  for (let i = 0; i < n; i += 1) {
    const format = u32();
    const len = u32();
    const end = o + len;
    const s = { enterprise: format >>> 12, type: format & 0xfff, frames: [], rates: [] };
    if (s.type === 3) { // expanded flow sample
      o += 4 + 8; // seq + source id (type, index)
      s.rates.push(u32());
      o += 4 + 4 + 16; // pool, drops, input/output (format, value)
      const records = u32();
      for (let r = 0; r < records; r += 1) {
        const rf = u32();
        const rl = u32();
        if ((rf & 0xfff) === 1 && rf >>> 12 === 0) {
          s.headerProtocol = buf.readUInt32BE(o);
          s.frames.push(buf.readUInt32BE(o + 4));
          s.headerLength = buf.readUInt32BE(o + 12);
        }
        o += rl;
      }
    }
    o = end;
    samples.push(s);
  }
  return { version, addrType, agent, subAgent, sequence, samples, trailing: buf.length - o };
}

test('fixtures: a run of real hsflowd datagrams is present', () => {
  assert.ok(FILES.length >= 20, `expected the captured run, found ${FILES.length}`);
});

test('every real datagram walks cleanly: sFlow v5, IPv4 agent 192.0.2.2, sequence 1..N', () => {
  FILES.forEach((f, i) => {
    const w = walk(load(f));
    assert.equal(w.version, 5, f);
    assert.equal(w.addrType, 1, f);
    assert.equal(w.agent, AGENT, f);
    assert.equal(w.subAgent, 100000, f); // hsflowd's fixed sub-agent id
    assert.equal(w.sequence, i + 1, `${f}: consecutive datagram sequence`);
    assert.equal(w.trailing, 0, `${f}: samples account for every byte`);
    for (const s of w.samples) {
      assert.equal(s.enterprise, 0, f);
      assert.ok([3, 4].includes(s.type), `${f}: hsflowd sends expanded samples, got ${s.type}`);
    }
  });
});

test('parseSflow reads each real datagram: one flow per flow sample, counter samples counted', () => {
  let flowSamples = 0;
  let counterSamples = 0;
  for (const f of FILES) {
    const buf = load(f);
    const w = walk(buf);
    const r = parseSflow(buf);
    const nFlow = w.samples.filter((s) => s.type === 3).length;
    const nCounter = w.samples.filter((s) => s.type === 4).length;
    assert.equal(r.header.version, 5, f);
    assert.equal(r.header.numSamples, w.samples.length, f);
    assert.equal(r.flows.length, nFlow, `${f}: every sampled frame here is IPv4 and decodes`);
    assert.equal(r.counterSamples, nCounter, f);
    flowSamples += nFlow;
    counterSamples += nCounter;
  }
  assert.ok(flowSamples >= 50, `a real run carries plenty of flow samples (${flowSamples})`);
  assert.ok(counterSamples >= 8, `and counter samples every polling interval (${counterSamples})`);
});

test('real flows: well-formed 5-tuples between the two veth ends, bytes = frame length × sampling rate', () => {
  for (const f of FILES) {
    const buf = load(f);
    const frames = walk(buf).samples.filter((s) => s.type === 3);
    const { flows } = parseSflow(buf);
    flows.forEach((fl, i) => {
      const s = frames[i];
      assert.equal(s.rates[0], SAMPLING_RATE, `${f}: configured 1-in-8 reaches the wire`);
      assert.equal(s.headerProtocol, 1, `${f}: Ethernet`);
      assert.ok(s.headerLength > 0 && s.headerLength <= 128, `${f}: header bytes ${s.headerLength}`);

      assert.equal(net.isIPv4(fl.srcAddr), true, `${f}: ${fl.srcAddr}`);
      assert.equal(net.isIPv4(fl.dstAddr), true, `${f}: ${fl.dstAddr}`);
      assert.ok(HOSTS.has(fl.srcAddr) && HOSTS.has(fl.dstAddr), `${f}: ${fl.srcAddr} -> ${fl.dstAddr}`);
      assert.notEqual(fl.srcAddr, fl.dstAddr);
      assert.ok([1, 6, 17].includes(fl.protocol), `${f}: protocol ${fl.protocol}`);
      if (fl.protocol === 1) {
        assert.equal(fl.protocolName, 'icmp');
        assert.equal(fl.srcPort, 0);
        assert.equal(fl.dstPort, 0);
      } else {
        assert.ok(Number.isInteger(fl.srcPort) && fl.srcPort > 0 && fl.srcPort <= 65535, `${f}: srcPort`);
        assert.ok(Number.isInteger(fl.dstPort) && fl.dstPort > 0 && fl.dstPort <= 65535, `${f}: dstPort`);
        const service = fl.protocol === 6 ? 8080 : 5353;
        assert.ok(fl.srcPort === service || fl.dstPort === service, `${f}: ${fl.protocolName} on :${service}`);
        // the service end is always the namespace side
        const serverIp = fl.srcPort === service ? fl.srcAddr : fl.dstAddr;
        assert.equal(serverIp, '198.51.100.2', f);
      }
      assert.equal(fl.sampled, true);
      assert.equal(fl.packets, SAMPLING_RATE, `${f}: one sampled packet stands for 8`);
      assert.equal(fl.bytes, s.frames[0] * SAMPLING_RATE, `${f}: frame length ${s.frames[0]} × rate`);
      // a frame is at least Ethernet + IPv4 + ICMP/UDP/TCP. The upper bound is
      // NOT the MTU: hsflowd samples through pcap, which sees TSO/GRO
      // super-frames on a host (3820 bytes here), so it is the IPv4 maximum.
      assert.ok(s.frames[0] >= 42 && s.frames[0] <= 65535 + 18, `${f}: frame ${s.frames[0]}`);
    });
  }
});

test('the real run aggregates into the three services that were exercised', () => {
  const flows = FILES.flatMap((f) => parseSflow(load(f)).flows);
  const agg = aggregateFlows(flows);

  assert.equal(agg.totals.flows, flows.length);
  assert.equal(agg.totals.packets, flows.length * SAMPLING_RATE);
  assert.equal(agg.totals.bytes, flows.reduce((a, f) => a + f.bytes, 0));

  const protos = new Set(agg.byProtocol.map((p) => p.protocol));
  assert.deepEqual([...protos].sort(), ['icmp', 'tcp', 'udp']);
  const ports = new Set(agg.byPort.map((p) => p.port));
  assert.ok(ports.has(8080) && ports.has(5353) && ports.has(0), [...ports].join(','));
  // servicePort is min(src,dst): the ephemeral client ports never become a "service"
  assert.equal(agg.byPort.length, 3);

  // HTTP bodies of 20–39 kB dominate the byte count, as they did on the wire
  assert.equal(agg.byPort[0].port, 8080);
  assert.ok(agg.byPort[0].bytes > agg.byPort[1].bytes);

  // per-5-tuple list: only the two veth ends, both directions present
  for (const fl of agg.flows) {
    assert.ok(HOSTS.has(fl.srcIp) && HOSTS.has(fl.dstIp));
    assert.ok(['tcp', 'udp', 'icmp'].includes(fl.proto));
  }
  const pairs = new Set(agg.topTalkers.map((t) => t.pair));
  assert.ok(pairs.has('198.51.100.1->198.51.100.2') && pairs.has('198.51.100.2->198.51.100.1'));
});

test('the collector, fed the real run over a UDP socket, reports what the parser saw', async () => {
  let sock = null;
  const collector = createSflowCollector({
    port: 0,
    bindAddress: '127.0.0.1',
    createSocket: () => { sock = dgram.createSocket('udp4'); return sock; },
  });
  await collector.start();
  try {
    const { port } = sock.address();
    const tx = dgram.createSocket('udp4');
    for (const f of FILES) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve, reject) => tx.send(load(f), port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
    }
    tx.close();
    const deadline = Date.now() + 2000;
    while (collector.stats().datagrams < FILES.length && Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 10));
    }
    const expectedFlows = FILES.reduce((a, f) => a + parseSflow(load(f)).flows.length, 0);
    const expectedCounters = FILES.reduce((a, f) => a + parseSflow(load(f)).counterSamples, 0);
    const st = collector.stats();
    assert.equal(st.datagrams, FILES.length);
    assert.equal(st.dropped, 0);
    assert.equal(st.decodedFlows, expectedFlows);
    assert.equal(st.counterSamples, expectedCounters);
    const snap = collector.drain();
    assert.equal(snap.source, 'sflow');
    assert.equal(snap.sampled, true);
    assert.equal(snap.totals.flows, expectedFlows);
  } finally {
    collector.stop();
  }
});
