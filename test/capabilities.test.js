'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { detectCapabilities } = require('../src/capabilities');
const { createSampler } = require('../src/monitor');

test('detectCapabilities reports proc, snmp, netflow and sflow when available', () => {
  const caps = detectCapabilities({ canReadProc: () => true, hasSnmp: () => true, hasNetflow: () => true, hasSflow: () => true, version: '1.2.3' });
  assert.deepEqual(caps.sources, ['proc', 'snmp', 'netflow', 'sflow']);
  assert.equal(caps.agentVersion, '1.2.3');
});

test('detectCapabilities omits sources that are unavailable', () => {
  const noFlow = { hasNetflow: () => false, hasSflow: () => false };
  assert.deepEqual(detectCapabilities({ canReadProc: () => true, hasSnmp: () => false, ...noFlow }).sources, ['proc']);
  assert.deepEqual(detectCapabilities({ canReadProc: () => false, hasSnmp: () => true, ...noFlow }).sources, ['snmp']);
  assert.deepEqual(detectCapabilities({ canReadProc: () => false, hasSnmp: () => false, ...noFlow }).sources, []);
});

test('detectCapabilities includes netflow and sflow by default (built-in collectors)', () => {
  const caps = detectCapabilities({ canReadProc: () => false, hasSnmp: () => false });
  assert.deepEqual(caps.sources, ['netflow', 'sflow']);
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

test('createSampler builds a netflow sampler that starts/drains/stops', async () => {
  let started = 0;
  let stopped = 0;
  const fakeCollector = {
    start: async () => { started += 1; },
    drain: () => ({ source: 'netflow', totals: { bytes: 0, flows: 0 }, byPort: [], byProtocol: [], topTalkers: [] }),
    stop: () => { stopped += 1; },
  };
  const sampler = createSampler(
    { source: 'netflow', netflow: { port: 9995 } },
    { netflowFactory: () => fakeCollector }
  );
  assert.equal(typeof sampler, 'function');
  assert.equal(typeof sampler.stop, 'function');
  assert.equal(started, 1); // collector started immediately

  const snap = await sampler({ intervalMs: 10 });
  assert.equal(snap.source, 'netflow');

  sampler.stop();
  assert.equal(stopped, 1);
});

test('createSampler builds an sflow sampler that starts/drains/stops', async () => {
  let started = 0;
  let stopped = 0;
  const fakeCollector = {
    start: async () => { started += 1; },
    drain: () => ({ source: 'sflow', totals: { bytes: 0, flows: 0 }, byPort: [], byProtocol: [], topTalkers: [] }),
    stop: () => { stopped += 1; },
  };
  const sampler = createSampler(
    { source: 'sflow', sflow: { port: 6343 } },
    { sflowFactory: () => fakeCollector }
  );
  assert.equal(typeof sampler.stop, 'function');
  assert.equal(started, 1);
  const snap = await sampler({ intervalMs: 10 });
  assert.equal(snap.source, 'sflow');
  sampler.stop();
  assert.equal(stopped, 1);
});
