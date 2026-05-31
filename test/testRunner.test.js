'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { runTest } = require('../src/testRunner');

// A fake traffic sample so the test neither reads /proc nor waits.
const fakeSampler = async ({ intervalMs }) => ({
  intervalMs,
  elapsedSec: intervalMs / 1000,
  interfaces: [
    { iface: 'eth0', rxBytes: 1000, txBytes: 2000, rxPackets: 10, txPackets: 12, rxBytesPerSec: 1000, txBytesPerSec: 2000 },
  ],
  totals: { rxBytes: 1000, txBytes: 2000, rxPackets: 10, txPackets: 12, rxBytesPerSec: 1000, txBytesPerSec: 2000 },
});
// A fake system sampler so the test doesn't sleep on real cpu sampling.
const fakeSystem = async () => ({ cpuPercent: 12.5, cpuCount: 4, memUsedPercent: 40, uptimeSec: 99 });

test('runTest measures traffic + system and returns a result payload', async () => {
  const result = await runTest({ name: 'run-test', id: 5, intervalMs: 500 }, { sampler: fakeSampler, systemSampler: fakeSystem });

  assert.equal(result.name, 'run-test');
  assert.equal(result.commandId, 5);
  assert.equal(result.ok, true);
  assert.ok(result.startedAt && result.finishedAt);
  assert.equal(result.traffic.totals.rxBytes, 1000);
  assert.equal(result.traffic.interfaces[0].iface, 'eth0');
  assert.equal(result.system.cpuPercent, 12.5);
  assert.equal(result.system.memUsedPercent, 40);
});

test('runTest still returns traffic if system metrics fail', async () => {
  const result = await runTest({ intervalMs: 10 }, {
    sampler: fakeSampler,
    systemSampler: async () => { throw new Error('no /proc'); },
  });
  assert.equal(result.traffic.totals.rxBytes, 1000);
  assert.equal(result.system, null); // best-effort: failure -> null, traffic kept
});

test('runTest defaults the name and interval', async () => {
  let usedInterval;
  const result = await runTest(undefined, {
    sampler: async ({ intervalMs }) => {
      usedInterval = intervalMs;
      return { intervalMs, elapsedSec: 1, interfaces: [], totals: { rxBytes: 0, txBytes: 0 } };
    },
    systemSampler: fakeSystem,
  });
  assert.equal(result.name, 'traffic');
  assert.equal(result.commandId, null);
  assert.equal(usedInterval, 1000);
});
