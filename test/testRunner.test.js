'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { runTest } = require('../src/testRunner');

test('runTest returns a result payload reflecting the command', async () => {
  const result = await runTest({ name: 'run-test', id: 5 });
  assert.equal(result.name, 'run-test');
  assert.equal(result.commandId, 5);
  assert.equal(result.ok, true);
  assert.ok(result.startedAt && result.finishedAt);
  assert.equal(typeof result.metrics.uptimeSec, 'number');
  assert.ok(Array.isArray(result.metrics.loadavg));
});

test('runTest uses a default name when none is given', async () => {
  const result = await runTest();
  assert.equal(result.name, 'system-check');
  assert.equal(result.commandId, null);
});
