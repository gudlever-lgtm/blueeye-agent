'use strict';

// The result size guard (src/resultBudget.js) and the sFlow collector's side
// of it.
//
// The server refuses any single result over 65 535 bytes, and the refusal is a
// 400 for the WHOLE traffic report. What has to hold:
//   * a result is never sent over the limit;
//   * trimming happens in one fixed, logged order — the sFlow counter rotation
//     first (handed back to the collector for next interval), then the
//     smallest flows, then the smallest top talkers — and says what it cut;
//   * the totals are never touched;
//   * a result that fits is sent exactly as measured.
// And for the collector: every exporter heard from is named
// (`sflowExporters`), including one that sends only flow samples, and a busy
// flow summary no longer starves the counters for good.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  fitResult, fitToBudget, bytesOf, RESULT_BUDGET_BYTES, SERVER_MAX_RESULT_BYTES,
} = require('../src/resultBudget');
const {
  createSflowCollector, EXPORTERS_MAX, COUNTERS_FLOOR_BYTES, IF_COUNTER_FIELDS,
} = require('../src/sflow/collector');
const { ETHERNET_FIELDS } = require('../src/sflow/parse');
const { aggregateFlows } = require('../src/netflow/aggregate');
const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

// The server's own validator when the sister checkout is next to this one —
// the real "would this be a 400" — else the same limit, written down.
function serverAccepts(result) {
  try {
    // eslint-disable-next-line global-require
    const { validateResults } = require('../../blueeye-server/src/validation/resultsValidation');
    return !validateResults({ results: [result] }).errors;
  } catch {
    return bytesOf(result) <= SERVER_MAX_RESULT_BYTES;
  }
}

// ------------------------------------------------------------ synthetic data
// Uncompressed, every group four digits: the longest an address renders as.
const v6 = (a, b) => `fd12:3456:789a:bcde:f012:${(0x1000 + a).toString(16)}:789a:${(0x1000 + b).toString(16)}`;

function ipv6Flows(n) {
  return Array.from({ length: n }, (_, i) => ({
    srcIp: v6(i, 1), dstIp: v6(i, 2), proto: 'tcp', srcPort: 50000 + i, dstPort: 44300,
    bytes: 987_654_321_098 - i * 1000, packets: 6_543_210_987 + i, flows: 1_234_567 + i,
    vlan: 4000 + (i % 90), inIf: 1_000_000_000 + i, outIf: 2_000_000_000 + i,
  }));
}
const talkers = (n) => Array.from({ length: n }, (_, i) => ({
  pair: `${v6(i, 1)}->${v6(i, 2)}`, bytes: 9_000_000_000 - i * 1000, packets: 6_000_000, flows: 1000,
}));
const counter = (i) => ({
  agent: v6(900, i), ifIndex: 1000 + i, at: 1_758_000_000_000, uptimeMs: 4_000_000_000,
  ifType: 6, speed: 10_000_000_000, direction: 1, status: 3,
  if: IF_COUNTER_FIELDS.map(() => 4_000_000_000), eth: ETHERNET_FIELDS.map(() => 4_000_000_000),
});

// A traffic result shaped exactly as runTest() builds it.
function bigResult({ flows = 200, topTalkers = 50, counters = 60 } = {}) {
  return {
    name: 'auto-report',
    commandId: null,
    ok: true,
    startedAt: '2026-09-24T10:00:00.000Z',
    finishedAt: '2026-09-24T10:00:01.000Z',
    traffic: {
      source: 'sflow', datagrams: 123456, droppedDatagrams: 0, sampled: true,
      totals: { bytes: 987654321000, packets: 123456789, flows: 424242 },
      byPort: Array.from({ length: 50 }, (_, i) => ({ port: 1000 + i, bytes: 1e9, packets: 1e6, flows: 1e3 })),
      byProtocol: [{ protocol: 'tcp', bytes: 1e12, packets: 1e9, flows: 1e6 }],
      topTalkers: talkers(topTalkers),
      flows: ipv6Flows(flows),
      sflowCounters: Array.from({ length: counters }, (_, i) => counter(i)),
    },
    system: {
      cpuPercent: 12.5, cpuCount: 64, loadavg: [1.25, 1.5, 1.75], memTotalBytes: 274877906944,
      memUsedBytes: 137438953472, memFreeBytes: 137438953472, memUsedPercent: 50, uptimeSec: 31536000,
    },
  };
}

// ------------------------------------------------------------- the guard
test('200 IPv6 flows alone are ~50-58 KB — the premise of the guard', () => {
  // The audit measured ~57.5 KB; the exact figure moves with the digit
  // widths of the counts. Either way it is most of the server's 64 KB.
  const size = bytesOf(ipv6Flows(200));
  assert.ok(size > 48_000 && size < 62_000, `200 IPv6 flows = ${size} bytes`);
});

test('an oversize result is trimmed under the budget in the fixed order, and says so', () => {
  const input = bigResult();
  const before = JSON.stringify(input);
  assert.ok(bytesOf(input) > SERVER_MAX_RESULT_BYTES, `the synthetic result is oversize (${bytesOf(input)})`);
  assert.equal(serverAccepts(input), false, 'and the server would refuse it whole');

  const fitted = fitResult(input);
  assert.equal(fitted.oversize, false);
  assert.ok(fitted.bytes <= RESULT_BUDGET_BYTES, `${fitted.bytes} <= ${RESULT_BUDGET_BYTES}`);
  assert.equal(bytesOf(fitted.value), fitted.bytes);
  assert.ok(serverAccepts(fitted.value), 'the server accepts what is sent');
  assert.equal(JSON.stringify(input), before, 'the measured result was not mutated');

  const t = fitted.value.traffic;
  // 1. The counter rotation went first, and ALL of it before any flow.
  assert.equal(fitted.removed['traffic.sflowCounters'].length, 60);
  assert.equal(t.sflowCounters.length, 0);
  // 2. Then the SMALLEST flows (the list is sorted by bytes, largest first).
  const cut = fitted.removed['traffic.flows'];
  assert.ok(cut.length > 0 && cut.length < 200);
  assert.equal(t.flows.length + cut.length, 200);
  assert.ok(Math.min(...t.flows.map((f) => f.bytes)) > Math.max(...cut.map((f) => f.bytes)),
    'every kept flow is bigger than every trimmed one');
  // 3. Top talkers were not needed.
  assert.equal(t.topTalkers.length, 50);
  assert.equal(fitted.removed['traffic.topTalkers'], undefined);
  // The totals are what was measured, untouched.
  assert.deepEqual(t.totals, input.traffic.totals);
  assert.deepEqual(fitted.value.system, input.system);
  // The marker names what went.
  assert.deepEqual(fitted.value.truncated, {
    budgetBytes: RESULT_BUDGET_BYTES,
    originalBytes: bytesOf(input),
    removed: { 'traffic.sflowCounters': 60, 'traffic.flows': cut.length },
  });
});

test('when dropping counters is enough, no flow is touched', () => {
  const input = bigResult({ flows: 150, counters: 200 });
  assert.ok(bytesOf(input) > RESULT_BUDGET_BYTES);
  const fitted = fitResult(input);
  assert.ok(fitted.bytes <= RESULT_BUDGET_BYTES);
  assert.ok(fitted.value.traffic.sflowCounters.length > 0, 'only the rotation tail went');
  assert.equal(fitted.value.traffic.flows.length, 150);
  assert.deepEqual(Object.keys(fitted.value.truncated.removed), ['traffic.sflowCounters']);
  // The removed ones are the TAIL, in their original order.
  const removed = fitted.removed['traffic.sflowCounters'];
  assert.deepEqual(removed.map((c) => c.ifIndex), input.traffic.sflowCounters.slice(-removed.length).map((c) => c.ifIndex));
});

test('top talkers go after the flows, smallest first', () => {
  const input = bigResult({ flows: 0, counters: 0, topTalkers: 600 });
  const fitted = fitResult(input);
  assert.ok(fitted.bytes <= RESULT_BUDGET_BYTES);
  const kept = fitted.value.traffic.topTalkers;
  assert.ok(kept.length < 600 && kept.length > 0);
  assert.equal(kept[kept.length - 1].bytes, input.traffic.topTalkers[kept.length - 1].bytes);
});

test('a result that fits is sent exactly as measured — same object, no marker', () => {
  const input = bigResult({ flows: 20, counters: 5 });
  const fitted = fitResult(input);
  assert.equal(fitted.value, input);
  assert.equal(fitted.marker, null);
  assert.equal('truncated' in fitted.value, false);
});

test('when no list can make it fit, the traffic is reduced to its totals', () => {
  const input = bigResult({ flows: 0, counters: 0, topTalkers: 0 });
  input.traffic.sflowExporters = Array.from({ length: 2000 }, (_, i) => v6(i, i));
  const fitted = fitResult(input);
  assert.equal(fitted.oversize, false);
  assert.ok(fitted.bytes <= RESULT_BUDGET_BYTES);
  assert.deepEqual(fitted.value.traffic.totals, input.traffic.totals);
  assert.equal(fitted.value.traffic.source, 'sflow');
  assert.ok(fitted.value.truncated.removed.trafficDetail.includes('sflowExporters'));
});

test('something that cannot be made to fit is flagged oversize, never passed as fitting', () => {
  const fitted = fitToBudget({ blob: 'x'.repeat(70_000) }, { maxBytes: RESULT_BUDGET_BYTES });
  assert.equal(fitted.oversize, true);
});

// ------------------------------------------------- the runtime, end to end
test('the runtime sends the trimmed result and hands the trimmed counters back', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const requeued = [];
  const warnings = [];
  const samplerFactory = () => {
    const sampler = async () => bigResult().traffic;
    sampler.requeueCounters = (list) => { requeued.push(...list); };
    return sampler;
  };
  const runtime = createAgentRuntime({
    config: {
      serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 },
      reportIntervalMs: 60000, reportSampleMs: 1,
    },
    token: 'valid',
    agentId: 1,
    logger: { ...silentLogger, warn: (m) => warnings.push(m) },
    samplerFactory,
    systemSampler: async () => bigResult().system,
  });
  try {
    assert.equal(await runtime.reportNow(), true);
    const sent = server.receivedResults[server.receivedResults.length - 1].results[0];
    assert.ok(bytesOf(sent) <= RESULT_BUDGET_BYTES, `sent ${bytesOf(sent)} bytes`);
    assert.ok(serverAccepts(sent));
    assert.equal(sent.truncated.removed['traffic.sflowCounters'], 60);
    assert.ok(sent.truncated.removed['traffic.flows'] > 0);
    assert.equal(requeued.length, 60, 'every trimmed counter reading went back to the collector');
    assert.ok(warnings.some((w) => /over the 60000-byte budget; trimmed sflowCounters 60, flows \d+/.test(w)), warnings.join('\n'));
  } finally {
    runtime.stop();
    await server.close();
  }
});

// -------------------------------------------------------------- the collector
const be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; };
const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n), 0); return b; };
const record = (type, body) => Buffer.concat([be(type), be(body.length), body]);

function datagram(samples, agent) {
  const isV6 = agent.length === 16;
  return Buffer.concat([be(5), be(isV6 ? 2 : 1), Buffer.from(agent), be(0), be(1), be(1000), be(samples.length), ...samples]);
}
const V6_AGENT = (n) => [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (n >> 8) & 255, n & 255];

// An 802.1Q-tagged IPv6/TCP frame between two full-width addresses.
function v6Frame(i) {
  const eth = Buffer.from([0, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x81, 0x00, 0x0f, 0xa0, 0x86, 0xdd]);
  const ip = Buffer.alloc(40);
  ip[0] = 0x60; ip[6] = 6;
  const addr = (o, last) => {
    [0xfd12, 0x3456, 0x789a, 0xbcde, 0xf012, 0x1000 + i, 0x789a, last].forEach((w, k) => ip.writeUInt16BE(w, o + k * 2));
  };
  addr(8, 0x1001);
  addr(24, 0x1002);
  const l4 = Buffer.alloc(4);
  l4.writeUInt16BE(50000 + i, 0); l4.writeUInt16BE(443, 2);
  return Buffer.concat([eth, ip, l4]);
}
function flowSample(i) {
  const raw = v6Frame(i);
  const hdr = Buffer.concat([be(1), be(1500), be(0), be(raw.length), raw]);
  const records = [record(1, hdr)];
  const body = Buffer.concat([
    be(1), be(3), be(1000 + (i % 7)), be(0), be(0), be(1_000_000 + i), be(2_000_000 + i), be(records.length), ...records,
  ]);
  return Buffer.concat([be(1), be(body.length), body]);
}
function counterSample(ifIndex) {
  const g = Buffer.concat([
    be(ifIndex), be(6), be64(1e10), be(1), be(3), be64(5e10), be(1), be(2), be(3), be(4), be(5), be(6),
    be64(6e10), be(7), be(8), be(9), be(10), be(11), be(0),
  ]);
  const eth = Buffer.concat(ETHERNET_FIELDS.map((_, k) => be(k)));
  const body = Buffer.concat([be(1), be(ifIndex), be(2), record(1, g), record(2, eth)]);
  return Buffer.concat([be(2), be(body.length), body]);
}

test('sflowExporters names every exporter heard from — a flow-only one included — IPv6 compressed', () => {
  const col = createSflowCollector();
  col._feed(datagram([flowSample(1)], [10, 14, 0, 2])); // flows only
  col._feed(datagram([flowSample(2)], V6_AGENT(1))); // flows only, IPv6
  col._feed(datagram([counterSample(5)], [10, 14, 0, 3])); // counters only
  col._feed(datagram([flowSample(3)], [10, 14, 0, 2])); // the first one again
  const snap = col.drain();
  assert.deepEqual(snap.sflowExporters, ['10.14.0.2', '2001:db8::1', '10.14.0.3']);
  assert.equal(col.drain().sflowExporters, undefined, 'per interval: nothing heard, no key');
});

test('sflowExporters is bounded', () => {
  const col = createSflowCollector();
  for (let n = 1; n <= EXPORTERS_MAX + 50; n += 1) col._feed(datagram([flowSample(n % 100)], V6_AGENT(n)));
  assert.equal(col.drain().sflowExporters.length, EXPORTERS_MAX);
});

test('worst case: 200+ IPv6 flows, 256 IPv6 exporters and a full counter backlog still fit — and the counters are not starved', () => {
  let t = 1_000_000;
  const col = createSflowCollector({ now: () => t });
  const seenCounters = new Set();
  let trimmedFlows = 0;
  for (let round = 0; round < 3; round += 1) {
    // 400 counter interfaces pending, 300 distinct IPv6 conversations, and
    // 256 IPv6 exporters (the bound) — every list at or past its cap.
    for (let i = 1; i <= 400; i += 1) col._feed(datagram([counterSample(i)], V6_AGENT(4000)));
    for (let i = 0; i < 300; i += 1) col._feed(datagram([flowSample(i)], V6_AGENT(1 + (i % EXPORTERS_MAX))));
    for (let n = 1; n <= EXPORTERS_MAX; n += 1) col._feed(datagram([flowSample(n % 300)], V6_AGENT(n)));
    t += 60_000;
    const snapshot = col.drain();
    assert.equal(snapshot.sflowExporters.length, EXPORTERS_MAX);
    assert.ok(snapshot.flows.length > 0, 'flows are still reported');
    assert.ok(snapshot.sflowCounters && snapshot.sflowCounters.length > 0, `round ${round}: counters got their floor`);
    assert.ok(bytesOf(snapshot.sflowCounters) >= COUNTERS_FLOOR_BYTES * 0.8);
    snapshot.sflowCounters.forEach((c) => seenCounters.add(c.ifIndex));
    if (snapshot.truncated) trimmedFlows += snapshot.truncated.removed.flows || 0;
    // Wrapped as runTest() wraps it, with the system metrics: under the guard's
    // budget without the guard having to cut anything.
    const result = {
      name: 'auto-report', commandId: null, ok: true,
      startedAt: '2026-09-24T10:00:00.000Z', finishedAt: '2026-09-24T10:00:01.000Z',
      traffic: snapshot, system: bigResult().system,
    };
    const fitted = fitResult(result);
    assert.ok(bytesOf(result) <= RESULT_BUDGET_BYTES, `round ${round}: ${bytesOf(result)} bytes`);
    assert.equal(fitted.marker, null, 'the guard had nothing to do');
    assert.ok(serverAccepts(result));
  }
  assert.ok(trimmedFlows > 0, 'the smallest flows made way, and the snapshot said so');
  assert.ok(seenCounters.size >= 100, `the rotation kept moving (${seenCounters.size} interfaces in 3 rounds)`);
});

test('requeued counter readings go out next time, and a newer reading wins over a returned one', () => {
  let t = 1_000_000;
  const col = createSflowCollector({ now: () => t });
  col._feed(datagram([counterSample(1), counterSample(2)], [10, 14, 0, 2]));
  const first = col.drain().sflowCounters;
  assert.equal(first.length, 2);
  t += 1000;
  col._feed(datagram([counterSample(2)], [10, 14, 0, 2])); // a newer reading for ifIndex 2
  assert.equal(col.requeueCounters(first), 1, 'only ifIndex 1 goes back; 2 has a newer reading');
  t += 1000;
  const second = col.drain().sflowCounters;
  assert.deepEqual(second.map((c) => c.ifIndex).sort(), [1, 2]);
  assert.equal(second.find((c) => c.ifIndex === 2).at, 1_001_000, 'the newer reading');
});

test('aggregateFlows output is what the guard assumes: flows and topTalkers sorted largest first', () => {
  const agg = aggregateFlows([
    { srcAddr: 'a', dstAddr: 'b', bytes: 5, packets: 1 },
    { srcAddr: 'c', dstAddr: 'd', bytes: 50, packets: 1 },
    { srcAddr: 'e', dstAddr: 'f', bytes: 20, packets: 1 },
  ]);
  assert.deepEqual(agg.flows.map((f) => f.bytes), [50, 20, 5]);
  assert.deepEqual(agg.topTalkers.map((f) => f.bytes), [50, 20, 5]);
});
