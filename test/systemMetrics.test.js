'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { sampleSystem, cpuTotals } = require('../src/systemMetrics');

// Two cpu snapshots: between them, 200 of 1000 ticks were non-idle -> 80% idle,
// so 20% busy across the interval.
const cpusA = () => [
  { times: { user: 100, nice: 0, sys: 50, idle: 800, irq: 0 } },
  { times: { user: 100, nice: 0, sys: 50, idle: 800, irq: 0 } },
];
let phase = 0;
const cpusStep = () => {
  // first call returns A, second returns A + 500 total (100 idle, 400 busy)/core
  const base = phase++ === 0 ? 0 : 1;
  return [
    { times: { user: 100 + base * 400, nice: 0, sys: 50, idle: 800 + base * 100, irq: 0 } },
    { times: { user: 100 + base * 400, nice: 0, sys: 50, idle: 800 + base * 100, irq: 0 } },
  ];
};

test('cpuTotals sums idle and total ticks across cores', () => {
  const { idle, total } = cpuTotals(cpusA());
  assert.equal(idle, 1600); // 800 * 2
  assert.equal(total, 1900); // (100+50+800) * 2
});

test('sampleSystem computes cpu%, memory and uptime', async () => {
  phase = 0;
  const m = await sampleSystem({
    intervalMs: 5,
    cpus: cpusStep,
    totalmem: () => 8_000_000_000,
    freemem: () => 2_000_000_000,
    loadavg: () => [0.5, 0.4, 0.3],
    uptime: () => 12345,
    sleepFn: async () => {},
  });
  // per core: idleDelta 100, totalDelta 500 -> busy = 1 - 100/500 = 80%
  assert.equal(m.cpuPercent, 80);
  assert.equal(m.cpuCount, 2);
  assert.equal(m.memTotalBytes, 8_000_000_000);
  assert.equal(m.memUsedBytes, 6_000_000_000);
  assert.equal(m.memUsedPercent, 75);
  assert.deepEqual(m.loadavg, [0.5, 0.4, 0.3]);
  assert.equal(m.uptimeSec, 12345);
});

test('sampleSystem handles identical snapshots (0% busy, no divide-by-zero)', async () => {
  const m = await sampleSystem({
    intervalMs: 1,
    cpus: cpusA,
    totalmem: () => 100,
    freemem: () => 100,
    sleepFn: async () => {},
  });
  assert.equal(m.cpuPercent, 0);
  assert.equal(m.memUsedPercent, 0);
});
