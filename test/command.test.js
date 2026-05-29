'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { isRunTestCommand } = require('../src/command');

test('isRunTestCommand recognises run-test in several shapes', () => {
  assert.equal(isRunTestCommand('run test'), true);
  assert.equal(isRunTestCommand('run-test'), true);
  assert.equal(isRunTestCommand('RunTest'), true);
  assert.equal(isRunTestCommand({ name: 'run-test' }), true);
  assert.equal(isRunTestCommand({ action: 'runtest' }), true);
  assert.equal(isRunTestCommand({ type: 'run_test' }), true);
});

test('isRunTestCommand rejects anything else', () => {
  assert.equal(isRunTestCommand({ name: 'reboot' }), false);
  assert.equal(isRunTestCommand('shutdown'), false);
  assert.equal(isRunTestCommand(null), false);
  assert.equal(isRunTestCommand(42), false);
  assert.equal(isRunTestCommand({}), false);
});
