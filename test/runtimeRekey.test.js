'use strict';

// The server manages an installed agent — there is no shell on these hosts.
//
// The agent pins the server's release public key and refuses any update it
// cannot verify against it. When the server's signing key changes (rotated,
// regenerated, or its private half no longer decryptable), that refusal is
// permanent and nothing on the host can clear it. So the server sends `rekey`
// over the same channel that already carries `update` and `delete`, and the
// agent replaces its own trust anchor — in memory now, on disk for next time.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');
const keyStore = require('../src/release/keyStore');
const { signedPayload } = require('../src/commandAuth');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const makeConfig = (server) => ({ serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } });
const noopHsflowd = { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) };
const systemd = { sources: ['proc'], agentVersion: '0.2.0', managed: 'systemd' };

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
}

// A scratch state dir per test — the pinned key is written beside the token, and
// the systemd drop-in sync is a no-op here (no unit file in a temp dir).
function scratch(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-rekey-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
  return {
    dir,
    pinnedKeyPath: path.join(dir, 'release-key.pem'),
    unitDir: path.join(dir, 'systemd'),
  };
}

async function runtimeWith(t, { pinnedKey, pinnedKeyPath, extra = {} }) {
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });
  const runtime = createAgentRuntime({
    config: makeConfig(server), token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: noopHsflowd, capabilities: systemd,
    releasePublicKey: pinnedKey, pinnedKeyPath,
    // The unit sync is best-effort and host-specific; point it at a directory
    // with no unit so the tests exercise the part that must always work.
    keys: { ...keyStore, syncSystemdDropIn: () => ({ ok: false, reason: 'no systemd unit on this host' }) },
    ...extra,
  });
  t.after(() => runtime.stop());
  return { server, runtime };
}

test('a rekey command replaces the pinned key in memory and on disk', async (t) => {
  const sc = scratch(t);
  const oldKey = keyPair();
  const newKey = keyPair();
  const { server, runtime } = await runtimeWith(t, { pinnedKey: oldKey.pem, pinnedKeyPath: sc.pinnedKeyPath });

  const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey');
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
  server.sendCommandToAll({ name: 'rekey', id: 'k1', auditId: 55, publicKey: newKey.pem });

  const msg = await withTimeout(reported, 4000, 'no rekey action-result');
  assert.equal(msg.ok, true);
  assert.equal(msg.auditId, 55);

  // On disk, so a restart does not hand the old key back.
  assert.equal(keyStore.readPinnedKey(sc.pinnedKeyPath).trim(), newKey.pem.trim());

  // In memory, immediately — the update that follows a rekey has to verify
  // against the NEW key without waiting for a restart. Proof: a privileged
  // command signed with the OLD key is now refused.
  const { canonicalize } = require('../src/release/canonicalize');
  const stale = { name: 'update', auditId: 60, agentId: 1, issuedAt: new Date().toISOString() };
  stale.commandSignature = crypto.sign(null, Buffer.from(canonicalize(signedPayload(stale))), oldKey.privateKey).toString('base64');
  const refused = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'upgrade' && m.ok === false);
  server.sendCommandToAll({ ...stale, id: 'u1' });
  const verdict = await withTimeout(refused, 4000, 'the replaced key still verifies commands');
  assert.match(verdict.detail, /signature verification failed/);
});

test('a rekey the server signs with the key being replaced is a proper rotation', async (t) => {
  // The strict agent refuses anything unsigned, so this also proves the rotation
  // path works where signed commands are mandatory.
  const sc = scratch(t);
  const oldKey = keyPair();
  const newKey = keyPair();
  const { server, runtime } = await runtimeWith(t, {
    pinnedKey: oldKey.pem, pinnedKeyPath: sc.pinnedKeyPath, extra: { strictCommands: true },
  });

  const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey');
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');

  const command = { name: 'rekey', auditId: 56, publicKey: newKey.pem, agentId: 1, issuedAt: new Date().toISOString() };
  const { canonicalize } = require('../src/release/canonicalize');
  command.commandSignature = crypto.sign(null, Buffer.from(canonicalize(signedPayload(command))), oldKey.privateKey).toString('base64');
  server.sendCommandToAll({ ...command, id: 'k2' });

  const msg = await withTimeout(reported, 4000, 'no rekey action-result');
  assert.equal(msg.ok, true, msg.detail);
  assert.equal(keyStore.readPinnedKey(sc.pinnedKeyPath).trim(), newKey.pem.trim());
});

test('a strict agent refuses an UNSIGNED rekey, and keeps the key it had', async (t) => {
  const sc = scratch(t);
  const oldKey = keyPair();
  const { server, runtime } = await runtimeWith(t, {
    pinnedKey: oldKey.pem, pinnedKeyPath: sc.pinnedKeyPath, extra: { strictCommands: true },
  });

  const refused = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false);
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
  server.sendCommandToAll({ name: 'rekey', id: 'k3', auditId: 57, publicKey: keyPair().pem });

  const msg = await withTimeout(refused, 4000, 'no refusal');
  assert.match(msg.detail, /unsigned command/);
  assert.equal(keyStore.readPinnedKey(sc.pinnedKeyPath), '', 'nothing may be written on a refusal');
});

test('a rekey carrying something that is not an ed25519 public key is refused', async (t) => {
  const sc = scratch(t);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const { server, runtime } = await runtimeWith(t, { pinnedKey: keyPair().pem, pinnedKeyPath: sc.pinnedKeyPath });

  const refused = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false);
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
  server.sendCommandToAll({ name: 'rekey', id: 'k4', auditId: 58, publicKey: rsa });

  const msg = await withTimeout(refused, 4000, 'no refusal');
  assert.match(msg.detail, /ed25519/);
  assert.equal(keyStore.readPinnedKey(sc.pinnedKeyPath), '', 'a bad key must never replace a good one');
});

test('re-sending the same key is reported as unchanged, not as a replacement', async (t) => {
  const sc = scratch(t);
  const key = keyPair();
  const { server, runtime } = await runtimeWith(t, { pinnedKey: key.pem, pinnedKeyPath: sc.pinnedKeyPath });

  const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey');
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'no config');
  server.sendCommandToAll({ name: 'rekey', id: 'k5', auditId: 59, publicKey: key.pem });

  const msg = await withTimeout(reported, 4000, 'no rekey action-result');
  assert.equal(msg.ok, true);
  assert.match(msg.detail, /unchanged/);
});

test('the pinned file outranks the installer environment, base64 or PEM', () => {
  const { resolveReleasePublicKey } = require('../src/release/publicKey');
  const installed = keyStore.validatePublicKey(keyPair().pem).pem;
  const rekeyed = keyStore.validatePublicKey(keyPair().pem).pem;
  const env = { BLUEEYE_RELEASE_PUBLIC_KEY: Buffer.from(installed, 'utf8').toString('base64') };

  // No rekey yet: what the installer baked in.
  assert.equal(resolveReleasePublicKey(env, { pinnedPath: '/nope', readPinned: () => '' }).trim(), installed.trim());
  // After a rekey: the stored anchor, even though the unit still carries the old
  // key in its environment.
  assert.equal(resolveReleasePublicKey(env, { pinnedPath: '/pinned', readPinned: () => rekeyed }).trim(), rekeyed.trim());
});
