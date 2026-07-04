'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createSampler } = require('../src/monitor');

test('createSampler uses the injected Windows traffic factory when platform is win32', () => {
  let receivedOpts = null;
  const fakeSampler = () => {};
  const winTrafficFactory = (opts) => { receivedOpts = opts; return fakeSampler; };

  const sampler = createSampler({ source: 'proc' }, { platform: 'win32', winTrafficFactory });

  assert.equal(sampler, fakeSampler);
  assert.ok(receivedOpts);
});

test('createSampler falls back to the Windows factory for an unrecognised source on win32', () => {
  let calls = 0;
  const winTrafficFactory = () => { calls += 1; return () => {}; };

  createSampler({ source: 'bogus' }, { platform: 'win32', winTrafficFactory });

  assert.equal(calls, 1);
});

test('createSampler does not touch the Windows factory on linux', () => {
  let calls = 0;
  const winTrafficFactory = () => { calls += 1; return () => {}; };

  const sampler = createSampler({ source: 'proc' }, { platform: 'linux', winTrafficFactory });

  assert.equal(calls, 0);
  assert.equal(typeof sampler, 'function');
  assert.equal(sampler.stop, undefined);
});

test('createSampler still routes snmp/netflow/sflow sources regardless of platform', () => {
  let netflowCalls = 0;
  const netflowFactory = () => { netflowCalls += 1; return { start: async () => {}, drain: () => ({}), stop: () => {} }; };

  createSampler({ source: 'netflow', netflow: {} }, { platform: 'win32', netflowFactory });

  assert.equal(netflowCalls, 1);
});
