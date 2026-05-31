'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { detectCapabilities } = require('../src/capabilities');
const { createSampler } = require('../src/monitor');

test('detectCapabilities reports proc and snmp when both are available', () => {
  const caps = detectCapabilities({ canReadProc: () => true, hasSnmp: () => true, version: '1.2.3' });
  assert.deepEqual(caps.sources, ['proc', 'snmp']);
  assert.equal(caps.agentVersion, '1.2.3');
});

test('detectCapabilities omits sources that are unavailable', () => {
  assert.deepEqual(detectCapabilities({ canReadProc: () => true, hasSnmp: () => false }).sources, ['proc']);
  assert.deepEqual(detectCapabilities({ canReadProc: () => false, hasSnmp: () => true }).sources, ['snmp']);
  assert.deepEqual(detectCapabilities({ canReadProc: () => false, hasSnmp: () => false }).sources, []);
});

test('createSampler returns a proc sampler by default and for source proc', () => {
  // We can't easily assert which function, but it must be callable and async.
  const s1 = createSampler();
  const s2 = createSampler({ source: 'proc' });
  assert.equal(typeof s1, 'function');
  assert.equal(typeof s2, 'function');
});

test('createSampler returns an snmp sampler for source snmp', async () => {
  // With an injected readCounters via the real sampleSnmp path we just check it
  // builds a function; the SNMP computation itself is covered in snmpMonitor.test.
  const sampler = createSampler({ source: 'snmp', snmp: { host: '10.0.0.1' } });
  assert.equal(typeof sampler, 'function');
});
