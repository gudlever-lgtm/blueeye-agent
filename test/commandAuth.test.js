'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { verifyCommand, requireSignedCommands } = require('../src/commandAuth');
const { canonicalize } = require('../src/release/canonicalize');

// Mints a key pair and a signer that mirrors blueeye-server's commandSigner:
// agentId + issuedAt are added, then everything except the transport `id` and
// the signature itself is signed over the canonical bytes.
function makeSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const sign = (agentId, command, issuedAt = new Date().toISOString()) => {
    const payload = { ...command, agentId, issuedAt };
    const signature = crypto.sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64');
    return { ...payload, commandSignature: signature };
  };
  return { publicPem, sign };
}

test('an unsigned command is allowed by default and refused in strict mode', () => {
  const command = { name: 'delete', auditId: 7 };
  assert.deepEqual(verifyCommand(command, { publicKey: 'x', agentId: 3 }), { ok: true, signed: false });

  const strict = verifyCommand(command, { publicKey: 'x', agentId: 3, strict: true });
  assert.equal(strict.ok, false);
  assert.match(strict.reason, /requires signed commands/);
});

test('a correctly signed command verifies', () => {
  const { publicPem, sign } = makeSigner();
  const command = sign(3, { name: 'delete', auditId: 7 });
  assert.deepEqual(verifyCommand(command, { publicKey: publicPem, agentId: 3, strict: true }), { ok: true, signed: true });
});

test('the transport correlation id is outside the signature', () => {
  const { publicPem, sign } = makeSigner();
  // sendCommandAndWait stamps `id` on AFTER the command is signed, so a command
  // that gained one must still verify.
  const command = { ...sign(3, { name: 'update', version: '1.2.3' }), id: 's123-4' };
  assert.equal(verifyCommand(command, { publicKey: publicPem, agentId: 3 }).ok, true);
});

test('tampering with any signed field is caught', () => {
  const { publicPem, sign } = makeSigner();
  const command = sign(3, { name: 'install-tool', tool: 'traceroute', auditId: 7 });

  for (const tampered of [
    { ...command, tool: 'mtr' },
    { ...command, name: 'delete' },
    { ...command, auditId: 8 },
    { ...command, commandSignature: 'bm90LWEtc2ln' },
  ]) {
    const v = verifyCommand(tampered, { publicKey: publicPem, agentId: 3 });
    assert.equal(v.ok, false, `expected refusal for ${JSON.stringify(tampered).slice(0, 60)}`);
    assert.match(v.reason, /signature verification failed/);
  }
});

test('a command signed for another agent is refused (no fleet-wide replay)', () => {
  const { publicPem, sign } = makeSigner();
  const command = sign(3, { name: 'delete' });
  const v = verifyCommand(command, { publicKey: publicPem, agentId: 4 });
  assert.equal(v.ok, false);
  assert.match(v.reason, /signed for a different agent/);
});

test('a stale signed command is refused (no replay later)', () => {
  const { publicPem, sign } = makeSigner();
  const old = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const command = sign(3, { name: 'delete' }, old);
  const v = verifyCommand(command, { publicKey: publicPem, agentId: 3 });
  assert.equal(v.ok, false);
  assert.match(v.reason, /time window/);

  // …and clock skew inside the window is tolerated.
  const recent = sign(3, { name: 'delete' }, new Date(Date.now() - 60 * 1000).toISOString());
  assert.equal(verifyCommand(recent, { publicKey: publicPem, agentId: 3 }).ok, true);
});

test('a signature that cannot be checked fails CLOSED', () => {
  const { sign } = makeSigner();
  const command = sign(3, { name: 'update' });
  const v = verifyCommand(command, { publicKey: '', agentId: 3 });
  assert.equal(v.ok, false);
  assert.match(v.reason, /no release public key/);
});

test('a signed command naming no agent is refused', () => {
  const { publicPem } = makeSigner();
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  // Signed, well-formed, but with nothing binding it to one agent.
  const payload = { name: 'delete', issuedAt: new Date().toISOString() };
  const command = { ...payload, commandSignature: crypto.sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64') };
  const v = verifyCommand(command, { publicKey: publicPem, agentId: 3 });
  assert.equal(v.ok, false);
});

test('requireSignedCommands reads the env flag', () => {
  assert.equal(requireSignedCommands({}), false);
  assert.equal(requireSignedCommands({ BLUEEYE_REQUIRE_SIGNED_COMMANDS: '0' }), false);
  for (const v of ['1', 'true', 'YES', 'on']) {
    assert.equal(requireSignedCommands({ BLUEEYE_REQUIRE_SIGNED_COMMANDS: v }), true, v);
  }
});

// ---- the runtime actually refuses ----------------------------------------

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };
const systemd = { sources: ['proc'], agentVersion: '0.2.0', managed: 'systemd' };

test('in strict mode an unsigned delete is refused and nothing is wiped', async () => {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const calls = { wipe: 0, remove: 0 };
  const selfDeleter = { wipeToken: () => { calls.wipe += 1; }, remove: () => { calls.remove += 1; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfDeleter, capabilities: systemd, strictCommands: true,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'delete');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ name: 'delete', id: 'd1', auditId: 77 });
    const msg = await withTimeout(reported, 4000, 'no delete action-result');
    assert.equal(msg.ok, false);
    assert.equal(msg.auditId, 77, 'the operator still sees the action fail in the audit trail');
    assert.match(msg.detail, /requires signed commands/);
    assert.equal(calls.wipe, 0, 'the token must not be wiped');
    assert.equal(calls.remove, 0, 'the agent must not remove itself');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a delete signed by the server is accepted in strict mode', async () => {
  const { publicPem, sign } = makeSigner();
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const calls = { wipe: 0, remove: 0 };
  const selfDeleter = { wipeToken: () => { calls.wipe += 1; }, remove: () => { calls.remove += 1; } };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfDeleter, capabilities: systemd,
    strictCommands: true, releasePublicKey: publicPem,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'delete');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    server.sendCommandToAll({ ...sign(1, { name: 'delete', auditId: 78 }), id: 'd2' });
    const msg = await withTimeout(reported, 4000, 'no delete action-result');
    assert.equal(msg.ok, true);
    assert.equal(calls.wipe, 1);
    assert.equal(calls.remove, 1);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an update signed for a DIFFERENT agent is refused without touching the updater', async () => {
  const { publicPem, sign } = makeSigner();
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  let updates = 0;
  const selfUpdater = { update: async () => { updates += 1; return { ok: true }; }, restart: () => {}, rollback: () => ({ ok: false }) };
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, selfUpdater, capabilities: systemd, releasePublicKey: publicPem,
  });
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'upgrade');
    runtime.start();
    await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
    // Captured from agent 2 and replayed here.
    server.sendCommandToAll({ ...sign(2, { name: 'update', version: '9.9.9', auditId: 79 }), id: 'u1' });
    const msg = await withTimeout(reported, 4000, 'no upgrade action-result');
    assert.equal(msg.ok, false);
    assert.match(msg.detail, /different agent/);
    assert.equal(updates, 0, 'the self-updater must not run');
  } finally {
    runtime.stop();
    await server.close();
  }
});
