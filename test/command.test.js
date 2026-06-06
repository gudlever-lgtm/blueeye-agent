'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { isRunTestCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand, isDiagnoseCommand } = require('../src/command');

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

test('isPingCommand recognises ping and rejects others', () => {
  assert.equal(isPingCommand('ping'), true);
  assert.equal(isPingCommand({ name: 'ping', id: 'x' }), true);
  assert.equal(isPingCommand('PING'), true);
  assert.equal(isPingCommand('run-test'), false);
  assert.equal(isPingCommand({ name: 'update' }), false);
  assert.equal(isPingCommand(null), false);
});

test('isUpdateCommand recognises update/upgrade and rejects others', () => {
  assert.equal(isUpdateCommand('update'), true);
  assert.equal(isUpdateCommand('upgrade'), true);
  assert.equal(isUpdateCommand('self-update'), true);
  assert.equal(isUpdateCommand({ name: 'update', sha256: 'a'.repeat(64) }), true);
  assert.equal(isUpdateCommand('ping'), false);
  assert.equal(isUpdateCommand({ name: 'run-test' }), false);
  assert.equal(isUpdateCommand(null), false);
});

test('isSpeedtestCommand recognises speedtest and rejects others', () => {
  assert.equal(isSpeedtestCommand('speedtest'), true);
  assert.equal(isSpeedtestCommand('speed-test'), true);
  assert.equal(isSpeedtestCommand({ name: 'speedtest', bytes: 2048 }), true);
  assert.equal(isSpeedtestCommand('ping'), false);
  assert.equal(isSpeedtestCommand({ name: 'run-test' }), false);
  assert.equal(isSpeedtestCommand(null), false);
});

test('isDiagnoseCommand recognises diagnose aliases and rejects others', () => {
  assert.equal(isDiagnoseCommand('diagnose'), true);
  assert.equal(isDiagnoseCommand('diag'), true);
  assert.equal(isDiagnoseCommand('doctor'), true);
  assert.equal(isDiagnoseCommand('self-check'), true);
  assert.equal(isDiagnoseCommand({ name: 'diagnose', id: 'x' }), true);
  assert.equal(isDiagnoseCommand('ping'), false);
  assert.equal(isDiagnoseCommand({ name: 'run-test' }), false);
  assert.equal(isDiagnoseCommand(null), false);
});
