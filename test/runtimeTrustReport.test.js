'use strict';

// WHICH KEY THIS AGENT TRUSTS, said out loud.
//
// The report that started this: an agent refused every update with "refused:
// command signature verification failed", and nothing anywhere could say why.
// The cause is mundane — the agent pins key A, the server signs with key B,
// usually because the server's key was regenerated after the agent was
// installed — and the fix is one re-pin from the dashboard. But the dashboard
// could not tell that case apart from a malformed signature, because the agent
// never said which key it holds. There is no shell on these hosts, so a fact
// the agent does not report is a fact nobody has.
//
// It reports a FINGERPRINT of the PUBLIC key. Not the key, and never anything
// secret: a digest is enough to compare two anchors and useless for anything
// else.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');
const keyStore = require('../src/release/keyStore');

const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };
const caps = { sources: ['proc'], agentVersion: '0.36.3', managed: 'systemd' };

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function publicPem() {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

async function reportedCapabilities(t, { releasePublicKey = null } = {}) {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: caps,
    releasePublicKey,
    keys: { ...keyStore, syncSystemdDropIn: () => ({ ok: false, reason: 'no systemd unit on this host' }) },
  });
  t.after(() => runtime.stop());
  runtime.start();
  // The capabilities POST and the config fetch both ride the same connect and
  // land in either order, so wait for the POST itself rather than for a
  // neighbour of it. An empty result here is a broken test, not a null report.
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
  for (let i = 0; i < 100 && !server.receivedCapabilities.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => { const t2 = setTimeout(r, 20); t2.unref(); });
  }
  assert.ok(server.receivedCapabilities.length, 'the agent reported its capabilities');
  return server.receivedCapabilities[0];
}

test('an agent that pins a key reports its fingerprint', async (t) => {
  const pem = publicPem();
  const reported = await reportedCapabilities(t, { releasePublicKey: pem });
  assert.equal(reported.releaseKeyFingerprint, keyStore.fingerprintOf(pem));
  // The comparison the dashboard makes is fingerprint-to-fingerprint, so the
  // two sides have to agree on how one is computed.
  assert.match(reported.releaseKeyFingerprint, /^[0-9a-f]{64}$/);
});

test('the key itself never leaves the host', async (t) => {
  const pem = publicPem();
  const reported = await reportedCapabilities(t, { releasePublicKey: pem });
  const body = JSON.stringify(reported);
  assert.ok(!body.includes('BEGIN PUBLIC KEY'), 'a fingerprint, not a key');
  assert.ok(!body.includes(pem.split('\n')[1]), 'and not any part of one');
});

test('an agent with no key pinned reports null, not a guess', async (t) => {
  const reported = await reportedCapabilities(t, { releasePublicKey: null });
  assert.equal(reported.releaseKeyFingerprint, null);
});

test('what the agent reports still says what it can DO', async (t) => {
  // The fingerprint rides along with the capabilities report; it must not
  // displace the thing that report exists for.
  const reported = await reportedCapabilities(t, { releasePublicKey: publicPem() });
  assert.deepEqual(reported.sources, ['proc']);
  assert.equal(reported.agentVersion, '0.36.3');
  assert.equal(reported.managed, 'systemd');
});
