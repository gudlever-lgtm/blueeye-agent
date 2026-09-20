'use strict';

// The agent half of the vendor-rooted trust chain.
//
// The question this answers is not "did the server ask nicely" but "is this
// agent allowed to take the server's word at all". It is not: the key an agent
// signs updates and privileged commands against is named inside a VENDOR-signed
// licence proof, and the agent verifies that against a key it embeds. A server
// that has been taken over can send anything it likes; without the vendor's
// signature over the fingerprint, none of it is accepted.
//
// The mandatory case, spelled out at the bottom: a compromised server generates
// an attacker key, sends a rekey, and the agent MUST reject it.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyTrustProof } = require('../src/license/trustProof');
const { resolveVendorRoot, EMBEDDED_VENDOR_ROOT_PUBLIC_KEY } = require('../src/license/vendorRoot');
const { publicKeyFingerprint } = require('../src/release/fingerprint');
const { canonicalize } = require('../src/release/canonicalize');
const keyStore = require('../src/release/keyStore');

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), publicKey, privateKey };
}

const VENDOR = keyPair();
const SERVER = keyPair();
const ATTACKER = keyPair();

// A proof exactly as blueeye-licens signs one.
function proofFor({
  key = SERVER.pem,
  sequence = 1,
  licenseId = '7',
  customerId = '42',
  serverId = 'server-abc',
  issuedAt = Date.now(),
  validForMs = 36 * 60 * 60 * 1000,
  signer = VENDOR.privateKey,
  mutate = null,
} = {}) {
  const payload = {
    valid: true,
    expiry: null,
    limits: { max_agents: 10 },
    plan: 'professional',
    features: null,
    serverId,
    issued_at: '2026-01-01T00:00:00.000Z',
    nonce: 'n',
    releases: null,
    proof_issued_at: new Date(issuedAt).toISOString(),
    valid_until: new Date(issuedAt + validForMs).toISOString(),
    trust: {
      license: { id: licenseId, customer_id: customerId },
      server: { id: serverId, release_key: { algorithm: 'Ed25519', fingerprint: publicKeyFingerprint(key) } },
      sequence,
    },
  };
  if (mutate) mutate(payload);
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), signer).toString('base64');
  return { payload, signature };
}

const verify = (opts) => verifyTrustProof({ vendorRoot: VENDOR.pem, ...opts });

// ---------------------------------------------------------------- positive

test('a valid vendor proof authorises the key it names', () => {
  const v = verify({ proof: proofFor(), offeredKey: SERVER.pem });
  assert.equal(v.ok, true, v.detail);
  assert.equal(v.fingerprint, publicKeyFingerprint(SERVER.pem));
  assert.equal(v.sequence, 1);
  assert.equal(v.licenseId, '7');
  assert.equal(v.customerId, '42');
});

test('a rotation to a new key is accepted when the sequence moves forward', () => {
  const rotated = keyPair();
  const v = verify({
    proof: proofFor({ key: rotated.pem, sequence: 5 }),
    offeredKey: rotated.pem,
    expected: { licenseId: '7', customerId: '42', sequence: 4 },
  });
  assert.equal(v.ok, true, v.detail);
  assert.equal(v.sequence, 5);
});

test('the same sequence is idempotent — a re-sent proof is not a rollback', () => {
  const v = verify({
    proof: proofFor({ sequence: 42 }),
    offeredKey: SERVER.pem,
    expected: { sequence: 42 },
  });
  assert.equal(v.ok, true, v.detail);
});

// ---------------------------------------------------------------- negative

test('a proof signed by anyone but the vendor is rejected', () => {
  // The interesting version of "wrong signer": the ATTACKER signs a proof that
  // authorises their own key, with everything else perfectly well-formed.
  const forged = proofFor({ key: ATTACKER.pem, signer: ATTACKER.privateKey });
  const v = verify({ proof: forged, offeredKey: ATTACKER.pem });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_PROOF_INVALID');
});

test('verifying against the wrong vendor root rejects a genuine proof', () => {
  const v = verifyTrustProof({ proof: proofFor(), offeredKey: SERVER.pem, vendorRoot: ATTACKER.pem });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_PROOF_INVALID');
});

test('a modified proof is rejected — every field is inside the signature', () => {
  const good = proofFor();
  for (const edit of [
    (p) => { p.trust.server.release_key.fingerprint = publicKeyFingerprint(ATTACKER.pem); },
    (p) => { p.trust.sequence = 99; },
    (p) => { p.trust.license.customer_id = '1'; },
    (p) => { p.valid_until = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000).toISOString(); },
  ]) {
    const tampered = { payload: JSON.parse(JSON.stringify(good.payload)), signature: good.signature };
    edit(tampered.payload);
    const v = verify({ proof: tampered, offeredKey: SERVER.pem });
    assert.equal(v.ok, false);
    assert.equal(v.code, 'LICENSE_PROOF_INVALID');
  }
});

test("another customer's valid proof authorises nothing here", () => {
  const v = verify({
    proof: proofFor({ licenseId: '9', customerId: '99' }),
    offeredKey: SERVER.pem,
    expected: { licenseId: '7', customerId: '42' },
  });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_CUSTOMER_MISMATCH');
});

test('an expired proof is rejected, and a future-dated one too', () => {
  const expired = verify({
    proof: proofFor({ issuedAt: Date.now() - 48 * 3600 * 1000, validForMs: 36 * 3600 * 1000 }),
    offeredKey: SERVER.pem,
  });
  assert.equal(expired.ok, false);
  assert.equal(expired.code, 'LICENSE_PROOF_EXPIRED');

  const future = verify({
    proof: proofFor({ issuedAt: Date.now() + 24 * 3600 * 1000 }),
    offeredKey: SERVER.pem,
  });
  assert.equal(future.ok, false);
  assert.equal(future.code, 'LICENSE_PROOF_INVALID');

  // Ordinary clock skew is tolerated — a host minutes out is not an attack.
  const skewed = verify({
    proof: proofFor({ issuedAt: Date.now() - 36 * 3600 * 1000 - 60_000 }),
    offeredKey: SERVER.pem,
  });
  assert.equal(skewed.ok, true, skewed.detail);
});

test('an older proof cannot roll the anchor back to a superseded key', () => {
  // The replay: a genuine proof, captured when the OLD key was authorised, sent
  // again after the key was rotated.
  const old = proofFor({ key: SERVER.pem, sequence: 3 });
  const v = verify({ proof: old, offeredKey: SERVER.pem, expected: { sequence: 7 } });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_PROOF_ROLLBACK');
});

test('a proof that authorises key A does not authorise key B', () => {
  const v = verify({ proof: proofFor({ key: SERVER.pem }), offeredKey: ATTACKER.pem });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'SERVER_KEY_MISMATCH');
});

test('malformed input is rejected, never thrown on', () => {
  const cases = [
    undefined, null, {}, { payload: null, signature: 'x' }, { payload: {}, signature: '' },
    { payload: { trust: null }, signature: 'x' },
    { payload: { trust: { server: { release_key: { fingerprint: 'nope' } }, sequence: 1 } }, signature: 'x' },
  ];
  for (const proof of cases) {
    const v = verify({ proof, offeredKey: SERVER.pem });
    assert.equal(v.ok, false, JSON.stringify(proof));
    assert.ok(v.code, 'every rejection must carry a code an operator can read');
  }
  // A proof with no trust block at all: a licence that has authorised no key.
  const none = verify({ proof: proofFor({ mutate: (p) => { delete p.trust; } }), offeredKey: SERVER.pem });
  assert.equal(none.ok, false);
  assert.equal(none.code, 'LICENSE_PROOF_INVALID');
});

test('an RSA key is refused even when the vendor signed its fingerprint', () => {
  // Defence in depth: the algorithm field and the agent's own key validation
  // both have to agree it is Ed25519.
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const v = verify({
    proof: proofFor({ key: rsa, mutate: (p) => { p.trust.server.release_key.algorithm = 'RSA'; } }),
    offeredKey: rsa,
  });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_PROOF_INVALID');
});

test('no vendor root means no trust — not an exception, and not a pass', () => {
  const v = verifyTrustProof({ proof: proofFor(), offeredKey: SERVER.pem, vendorRoot: '' });
  assert.equal(v.ok, false);
  assert.equal(v.code, 'LICENSE_PROOF_INVALID');
});

// ---------------------------------------------------------------- the anchor

test('the vendor root is embedded, and production ignores an unacknowledged override', () => {
  assert.match(EMBEDDED_VENDOR_ROOT_PUBLIC_KEY, /BEGIN PUBLIC KEY/);
  assert.equal(resolveVendorRoot({}), EMBEDDED_VENDOR_ROOT_PUBLIC_KEY);

  // Development may override — the demo stack and this test suite generate
  // their own vendor key.
  assert.equal(resolveVendorRoot({ BLUEEYE_VENDOR_ROOT_PUBLIC_KEY: VENDOR.pem }), VENDOR.pem);
  assert.equal(
    resolveVendorRoot({ BLUEEYE_VENDOR_ROOT_PUBLIC_KEY: Buffer.from(VENDOR.pem).toString('base64') }),
    VENDOR.pem
  );

  // Production does not: the operator setting it is the party the chain
  // constrains.
  assert.equal(
    resolveVendorRoot({ NODE_ENV: 'production', BLUEEYE_VENDOR_ROOT_PUBLIC_KEY: ATTACKER.pem }),
    EMBEDDED_VENDOR_ROOT_PUBLIC_KEY
  );
  assert.equal(
    resolveVendorRoot({
      NODE_ENV: 'production',
      BLUEEYE_VENDOR_ROOT_PUBLIC_KEY: VENDOR.pem,
      BLUEEYE_TRUST_ANCHOR_OVERRIDE_ACK: 'i-accept-the-risk',
    }),
    VENDOR.pem
  );
});

// ---------------------------------------------------------------- the latch

test('accepted trust is recorded, and the sequence floor only ever rises', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-trust-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
  const pinned = path.join(dir, 'release-key.pem');

  assert.deepEqual(keyStore.readTrustState(pinned).vendorRooted, false, 'a fresh agent is not latched');

  keyStore.writeTrustState(pinned, { sequence: 4, licenseId: '7', customerId: '42', fingerprint: publicKeyFingerprint(SERVER.pem) });
  let state = keyStore.readTrustState(pinned);
  assert.equal(state.sequence, 4);
  assert.equal(state.vendorRooted, true, 'accepting a vendor authorisation latches the agent');

  // Backwards is refused at the store, not just at the verifier.
  assert.equal(keyStore.writeTrustState(pinned, { sequence: 3 }), false);
  assert.equal(keyStore.readTrustState(pinned).sequence, 4);

  keyStore.writeTrustState(pinned, { sequence: 5 });
  assert.equal(keyStore.readTrustState(pinned).sequence, 5);

  // A corrupted file reads as "nothing accepted" — which asks for MORE proof,
  // never less. (The latch it loses is re-set by the next accepted proof.)
  fs.writeFileSync(keyStore.trustStatePath(pinned), 'not json');
  assert.equal(keyStore.readTrustState(pinned).sequence, null);
});

// ------------------------------------------------- the compromised server

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');
const { signedPayload } = require('../src/commandAuth');

const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message || `timeout ${ms}ms`)), ms); timer.unref(); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// An agent that has already accepted a vendor authorisation — i.e. one that has
// been through this chain once, which after migration is every agent.
async function latchedAgent(t, { sequence = 4, pinned = SERVER.pem } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-latched-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
  const pinnedKeyPath = path.join(dir, 'release-key.pem');
  fs.writeFileSync(pinnedKeyPath, pinned);
  keyStore.writeTrustState(pinnedKeyPath, {
    sequence, licenseId: '7', customerId: '42', fingerprint: publicKeyFingerprint(pinned),
  });

  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });
  const runtime = createAgentRuntime({
    config: { serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } },
    token: 'valid', agentId: 1, logger: silentLogger,
    capabilities: { sources: ['proc'], agentVersion: '0.34.0', managed: 'systemd' },
    hsflowdManager: { enable: async () => ({}), disable: async () => ({}), status: async () => ({}) },
    releasePublicKey: pinned,
    pinnedKeyPath,
    // The vendor key this agent verifies against. In production it is the
    // embedded constant; a test cannot hold the real vendor's private half.
    keys: { ...keyStore },
  });
  t.after(() => runtime.stop());
  process.env.BLUEEYE_VENDOR_ROOT_PUBLIC_KEY = VENDOR.pem;
  t.after(() => { delete process.env.BLUEEYE_VENDOR_ROOT_PUBLIC_KEY; });

  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'never connected');
  return { server, runtime, pinnedKeyPath };
}

test('MANDATORY: a compromised server cannot re-anchor an agent to a key of its own', async (t) => {
  const { server, pinnedKeyPath } = await latchedAgent(t);

  // The attacker owns the server: they can read its files, change its config,
  // sign commands with whatever key they hold, and send anything they like on
  // the agent's own channel. What they cannot do is produce a vendor signature.
  const refused = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false);

  // Attempt 1: a bare rekey to the attacker's key.
  server.sendCommandToAll({ name: 'rekey', id: 'x1', auditId: 1, publicKey: ATTACKER.pem });
  const first = await withTimeout(refused, 4000, 'no refusal');
  assert.match(first.detail, /vendor-signed authorisation/);

  // Attempt 2: the same, but signed with the key the agent currently trusts —
  // the attacker has the server's private key, after all. Still refused: once
  // vendor-rooted, only the vendor decides.
  const signedRefusal = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false && m.auditId === 2);
  const cmd = { name: 'rekey', auditId: 2, publicKey: ATTACKER.pem, agentId: 1, issuedAt: new Date().toISOString() };
  cmd.commandSignature = crypto.sign(null, Buffer.from(canonicalize(signedPayload(cmd)), 'utf8'), SERVER.privateKey).toString('base64');
  server.sendCommandToAll({ ...cmd, id: 'x2' });
  const second = await withTimeout(signedRefusal, 4000, 'no refusal for the signed attempt');
  assert.match(second.detail, /vendor-signed authorisation/);

  // Attempt 3: a proof the attacker signed themselves.
  const forgedRefusal = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false && m.auditId === 3);
  server.sendCommandToAll({
    name: 'rekey', id: 'x3', auditId: 3, publicKey: ATTACKER.pem,
    vendorProof: proofFor({ key: ATTACKER.pem, sequence: 99, signer: ATTACKER.privateKey }),
  });
  const third = await withTimeout(forgedRefusal, 4000, 'no refusal for the forged proof');
  assert.match(third.detail, /LICENSE_PROOF_INVALID/);

  // Attempt 4: a GENUINE old proof, replayed to roll the anchor back.
  const replayRefusal = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === false && m.auditId === 4);
  server.sendCommandToAll({
    name: 'rekey', id: 'x4', auditId: 4, publicKey: ATTACKER.pem,
    vendorProof: proofFor({ key: ATTACKER.pem, sequence: 2 }),
  });
  const fourth = await withTimeout(replayRefusal, 4000, 'no refusal for the replay');
  // The fingerprint belongs to the attacker AND the sequence is old; either is
  // fatal, and the rollback check runs first.
  assert.match(fourth.detail, /LICENSE_PROOF_ROLLBACK|SERVER_KEY_MISMATCH/);

  // Through all of it, the anchor on disk never moved.
  assert.equal(fs.readFileSync(pinnedKeyPath, 'utf8').trim(), SERVER.pem.trim());
  assert.equal(keyStore.readTrustState(pinnedKeyPath).sequence, 4);
});

test('a vendor-authorised rotation IS accepted, and raises the rollback floor', async (t) => {
  const { server, pinnedKeyPath } = await latchedAgent(t);
  const rotated = keyPair();

  const applied = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === true);
  server.sendCommandToAll({
    name: 'rekey', id: 'r1', auditId: 9, publicKey: rotated.pem,
    vendorProof: proofFor({ key: rotated.pem, sequence: 5 }),
  });
  const msg = await withTimeout(applied, 4000, 'the vendor-authorised rotation was not accepted');
  assert.match(msg.detail, /pinned/);

  assert.equal(fs.readFileSync(pinnedKeyPath, 'utf8').trim(), rotated.pem.trim());
  const state = keyStore.readTrustState(pinnedKeyPath);
  assert.equal(state.sequence, 5, 'the accepted sequence is the new rollback floor');
  assert.equal(state.fingerprint, publicKeyFingerprint(rotated.pem));
});

test('an agent that has never been vendor-rooted still accepts the old signed rotation', async (t) => {
  // Migration: every agent installed before this chain existed is in this
  // state. It must not be locked out — and the first vendor proof latches it.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-legacy-'));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });
  const pinnedKeyPath = path.join(dir, 'release-key.pem');
  fs.writeFileSync(pinnedKeyPath, SERVER.pem);
  assert.equal(keyStore.readTrustState(pinnedKeyPath).vendorRooted, false);

  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  t.after(async () => { await server.close(); });
  const runtime = createAgentRuntime({
    config: { serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } },
    token: 'valid', agentId: 1, logger: silentLogger,
    capabilities: { sources: ['proc'], agentVersion: '0.34.0', managed: 'systemd' },
    hsflowdManager: { enable: async () => ({}), disable: async () => ({}), status: async () => ({}) },
    releasePublicKey: SERVER.pem, pinnedKeyPath,
  });
  t.after(() => runtime.stop());
  runtime.start();
  await withTimeout(onceEvent(runtime, 'config'), 4000, 'never connected');

  const rotated = keyPair();
  const applied = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'rekey' && m.ok === true);
  const cmd = { name: 'rekey', auditId: 11, publicKey: rotated.pem, agentId: 1, issuedAt: new Date().toISOString() };
  cmd.commandSignature = crypto.sign(null, Buffer.from(canonicalize(signedPayload(cmd)), 'utf8'), SERVER.privateKey).toString('base64');
  server.sendCommandToAll({ ...cmd, id: 'l1' });

  await withTimeout(applied, 4000, 'the legacy signed rotation was refused');
  assert.equal(fs.readFileSync(pinnedKeyPath, 'utf8').trim(), rotated.pem.trim());
  // Still not latched: no vendor proof has been seen.
  assert.equal(keyStore.readTrustState(pinnedKeyPath).vendorRooted, false);
});
