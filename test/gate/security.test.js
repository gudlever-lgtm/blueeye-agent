'use strict';

// GATE · SECURITY — blueeye-agent
//
// Runs before every branch build (scripts/gate.sh). Pins the agent's
// fail-closed security contract: signed-command verification and replay
// bounds, token-file permissions, TLS certificate pinning, the same-host-only
// http→https self-heal, curl argument hardening, bounded server-supplied
// regexes, the tool-install and evidence allowlists, signed self-update, and
// a scan for committed secrets. One end-to-end case proves the runtime
// actually refuses an unsigned privileged command over the real WebSocket.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const { verifyCommand, signedPayload, requireSignedCommands, MAX_SKEW_MS } = require('../../src/commandAuth');
const { canonicalize } = require('../../src/release/canonicalize');
const { readToken, saveToken } = require('../../src/tokenStore');
const { checkPin } = require('../../src/httpsClient');
const { normalizeFingerprint } = require('../../src/fingerprint');
const { resolveEffectiveServerUrl } = require('../../src/serverUrl');
const { safeHeader, dataArgs } = require('../../src/probes/curlArgs');
const { compile, safeTest, safeExec } = require('../../src/probes/safeRegex');
const { createToolInstaller, ALLOWED_TOOLS } = require('../../src/toolInstaller');
const { createEvidenceCollector, isAllowed, READ_ONLY_ITEMS } = require('../../src/evidenceCollector');
const { createSelfUpdater } = require('../../src/selfUpdate');
const { silentLogger } = require('../../src/logger');

const ROOT = path.join(__dirname, '..', '..');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-gate-'));

function makeSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const sign = (agentId, cmd, issuedAt = new Date().toISOString()) => {
    const body = { ...cmd, agentId, issuedAt };
    return { ...body, commandSignature: crypto.sign(null, Buffer.from(canonicalize(signedPayload(body))), privateKey).toString('base64') };
  };
  return { publicPem, sign };
}

// ---------------------------------------------------------------- signed commands
test('commandAuth: strict mode refuses unsigned commands; lenient allows them', () => {
  assert.equal(verifyCommand({ name: 'delete' }, { strict: true }).ok, false);
  assert.equal(verifyCommand({ name: 'delete' }, { strict: false }).ok, true);
  assert.equal(verifyCommand(null, { strict: true }).ok, false, 'a null command must not pass');
  assert.equal(requireSignedCommands({ BLUEEYE_REQUIRE_SIGNED_COMMANDS: 'true' }), true);
  assert.equal(requireSignedCommands({ BLUEEYE_REQUIRE_SIGNED_COMMANDS: 'nope' }), false);
  assert.equal(requireSignedCommands({}), false);
});

test('commandAuth: a valid signature verifies; tampering, wrong agent, replay window and missing key all fail closed', () => {
  const { publicPem, sign } = makeSigner();
  const cmd = sign(7, { name: 'delete', auditId: 1 });
  assert.deepEqual(verifyCommand(cmd, { publicKey: publicPem, agentId: 7, strict: true }), { ok: true, signed: true });
  assert.equal(verifyCommand({ ...cmd, id: 'transport-id' }, { publicKey: publicPem, agentId: 7 }).ok, true, 'transport id is outside the signature');
  assert.equal(verifyCommand({ ...cmd, auditId: 2 }, { publicKey: publicPem, agentId: 7 }).ok, false, 'tampered field');
  assert.equal(verifyCommand({ ...cmd, name: 'update' }, { publicKey: publicPem, agentId: 7 }).ok, false, 'tampered verb');
  assert.equal(verifyCommand(cmd, { publicKey: publicPem, agentId: 8 }).ok, false, 'signed for another agent');
  assert.equal(verifyCommand(cmd, { publicKey: '', agentId: 7 }).ok, false, 'no public key → refuse, never trust a signature blindly');
  assert.equal(verifyCommand(cmd, { publicKey: makeSigner().publicPem, agentId: 7 }).ok, false, 'another key');
  const stale = sign(7, { name: 'delete' }, new Date(Date.now() - MAX_SKEW_MS - 60_000).toISOString());
  assert.equal(verifyCommand(stale, { publicKey: publicPem, agentId: 7 }).ok, false, 'outside the replay window');
  const future = sign(7, { name: 'delete' }, new Date(Date.now() + MAX_SKEW_MS + 60_000).toISOString());
  assert.equal(verifyCommand(future, { publicKey: publicPem, agentId: 7 }).ok, false, 'future-dated');
  const noAgent = { ...sign(7, { name: 'delete' }) }; delete noAgent.agentId;
  assert.equal(verifyCommand(noAgent, { publicKey: publicPem, agentId: 7 }).ok, false, 'names no agent');
  assert.ok(MAX_SKEW_MS <= 10 * 60 * 1000, 'replay window must stay tight');
  assert.doesNotThrow(() => verifyCommand({ commandSignature: 'not-base64!!', agentId: 7 }, { publicKey: publicPem, agentId: 7 }));
});

// ---------------------------------------------------------------- token at rest
test('tokenStore: token file is owner-only (0600), malformed files never throw', () => {
  const dir = tmp();
  const p = path.join(dir, 'nested', 'token');
  saveToken(p, { agentId: 3, token: 'secret-token' });
  if (process.platform !== 'win32') assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  assert.deepEqual(readToken(p), { agentId: 3, token: 'secret-token' });
  fs.writeFileSync(p, '{not json');
  assert.equal(readToken(p), null);
  fs.writeFileSync(p, JSON.stringify({ agentId: 3, token: '' }));
  assert.equal(readToken(p), null, 'an empty token is no token');
  assert.equal(readToken(path.join(dir, 'missing')), null);
});

// ---------------------------------------------------------------- TLS pinning
test('httpsClient.checkPin: mismatching certificate is rejected with CERT_FINGERPRINT_MISMATCH', () => {
  const fp = 'AA'.repeat(32);
  const pinned = checkPin(fp);
  const okCert = { fingerprint256: normalizeFingerprint(fp) };
  assert.equal(pinned('host', okCert), undefined);
  const err = pinned('host', { fingerprint256: normalizeFingerprint('BB'.repeat(32)) });
  assert.equal(err && err.code, 'CERT_FINGERPRINT_MISMATCH');
  assert.equal(pinned('host', null).code, 'CERT_FINGERPRINT_MISMATCH', 'no certificate is a mismatch');
  assert.equal(checkPin('')('host', { fingerprint256: 'anything' }), undefined, 'no pin configured = ordinary TLS validation');
  assert.equal(normalizeFingerprint('sha256:' + 'ab:'.repeat(31) + 'ab'), 'AB:'.repeat(31) + 'AB');
  assert.equal(normalizeFingerprint('tooshort'), '', 'a non-SHA-256 pin is ignored rather than mis-compared');
});

// ---------------------------------------------------------------- server URL self-heal
test('serverUrl: only a same-host http→https redirect is adopted; cross-host and downgrade redirects are refused', async () => {
  const redirectTo = (location) => async () => ({ status: 301, headers: { location }, json: null });
  const same = await resolveEffectiveServerUrl({ serverUrl: 'http://srv.example.dk', request: redirectTo('https://srv.example.dk/'), logger: silentLogger });
  assert.equal(same, 'https://srv.example.dk');
  const cross = await resolveEffectiveServerUrl({ serverUrl: 'http://srv.example.dk', request: redirectTo('https://evil.example.com/'), logger: silentLogger });
  assert.equal(cross, 'http://srv.example.dk', 'cross-host redirect must not be followed');
  const downgrade = await resolveEffectiveServerUrl({ serverUrl: 'https://srv.example.dk', request: async () => { throw new Error('must not probe https'); }, logger: silentLogger });
  assert.equal(downgrade, 'https://srv.example.dk');
  const toHttp = await resolveEffectiveServerUrl({ serverUrl: 'http://srv.example.dk', request: redirectTo('http://srv.example.dk:8080/'), logger: silentLogger });
  assert.equal(toHttp, 'http://srv.example.dk', 'a redirect that is not https is not an upgrade');
});

// ---------------------------------------------------------------- curl hardening
test('curlArgs: header values cannot read files or inject headers; bodies are always --data-raw', () => {
  for (const bad of ['@/etc/shadow', '@/root/.ssh/id_rsa', 'X-A: 1\r\nX-B: 2', '', ';', `X: ${'a'.repeat(5000)}`]) {
    assert.equal(safeHeader(bad), null, `accepted ${JSON.stringify(bad).slice(0, 40)}`);
  }
  assert.ok(safeHeader('Accept: application/json'));
  const args = dataArgs('@/etc/passwd');
  assert.ok(args.includes('--data-raw'), 'must use --data-raw');
  assert.ok(!args.includes('--data') || args.indexOf('--data') === -1, 'plain --data would read a file');
  assert.ok(!args.includes('-d'));
});

test('safeRegex: catastrophic and malformed server-supplied patterns are bounded', () => {
  const t0 = Date.now();
  assert.equal(safeTest(compile('^(a+)+$'), `${'a'.repeat(60)}b`, { timeoutMs: 150 }), false);
  assert.ok(Date.now() - t0 < 3000, 'ReDoS was not interrupted');
  assert.equal(compile('('), null);
  assert.equal(safeExec(null, 'x'), null);
  assert.equal(safeExec(compile('token=([a-z0-9]+)'), 'token=abc')[1], 'abc');
});

// ---------------------------------------------------------------- allowlists
test('toolInstaller: only the fixed allowlist can be installed, and a refused tool never shells out', async () => {
  assert.deepEqual([...ALLOWED_TOOLS].sort(), ['mtr', 'tcptraceroute', 'traceroute']);
  const record = [];
  const installer = createToolInstaller({ exec: async (cmd, args) => { record.push([cmd, ...args]); return { ok: true, stdout: '', stderr: '' }; } });
  for (const tool of ['curl; rm -rf /', 'traceroute && id', '../../bin/sh', 'nmap', '', null, { name: 'traceroute' }]) {
    const r = await installer.installTool({ tool });
    assert.equal(r.ok, false, `installed ${JSON.stringify(tool)}`);
    assert.equal(record.length, 0, `shelled out for ${JSON.stringify(tool)}`);
  }
});

test('evidenceCollector: only read-only items are collected; anything else is refused without running', async () => {
  assert.deepEqual([...READ_ONLY_ITEMS].sort(), ['agent.state', 'arp.table', 'iface.counters', 'snmp.reads']);
  for (const item of ['shell', 'token', '__proto__', 'constructor', '', null, 'iface.counters; id']) assert.equal(isAllowed(item), false, String(item));
  let ran = 0;
  const collector = createEvidenceCollector({ collectors: { 'arp.table': async () => { ran += 1; return 'arp'; }, shell: async () => { ran += 100; return 'pwned'; } } });
  const results = await collector.collect(['arp.table', 'shell', 'token']);
  assert.equal(ran, 1, 'the refused items must not execute even if a collector exists');
  assert.equal(results.find((r) => r.name === 'shell').status, 'refused');
  assert.equal(results.find((r) => r.name === 'token').status, 'refused');
  assert.equal(results.find((r) => r.name === 'arp.table').payload, 'arp');
});

// ---------------------------------------------------------------- signed self-update
test('selfUpdate: a bad or unverifiable signature never reaches extraction', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
  const tarball = Buffer.from('agent-release-bytes');
  const manifest = { version: '9.9.9', sha256: sha(tarball), size: tarball.length };
  const goodSig = crypto.sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64');
  const release = (sig, body = tarball) => async () => ({
    ok: true, status: 200,
    headers: { get: (n) => (n.toLowerCase() === 'x-release-manifest' ? Buffer.from(JSON.stringify(manifest)).toString('base64') : n.toLowerCase() === 'x-release-signature' ? sig : null) },
    arrayBuffer: async () => Uint8Array.from(body).buffer,
  });
  const run = async (opts) => {
    const calls = [];
    const updater = createSelfUpdater({ exec: (cmd) => { calls.push(cmd); return { status: 0, stdout: '', stderr: '' }; }, fsImpl: { mkdtempSync: () => '/tmp/u', writeFileSync() {}, rmSync() {} }, logger: { info() {}, warn() {}, error() {} } });
    const r = await updater.update({ serverUrl: 'http://s', token: 't', expectedVersion: '9.9.9', ...opts });
    return { r, calls };
  };
  const good = await run({ signature: goodSig, publicKey: pubPem, fetchImpl: release(goodSig) });
  assert.equal(good.r.ok, true);
  assert.ok(good.calls.includes('tar'));
  // Every refusal is a thrown, coded error — and extraction must never have started.
  const badSig = crypto.sign(null, Buffer.from(canonicalize({ ...manifest, version: '0.0.1' })), privateKey).toString('base64');
  const refused = async (label, opts, code) => {
    const calls = [];
    const updater = createSelfUpdater({ exec: (cmd) => { calls.push(cmd); return { status: 0, stdout: '', stderr: '' }; }, fsImpl: { mkdtempSync: () => '/tmp/u', writeFileSync() {}, rmSync() {} }, logger: { info() {}, warn() {}, error() {} } });
    await assert.rejects(() => updater.update({ serverUrl: 'http://s', token: 't', expectedVersion: '9.9.9', ...opts }), (e) => e.code === code, `${label}: expected ${code}`);
    assert.ok(!calls.includes('tar'), `${label}: extracted anyway`);
  };
  await refused('bad signature', { signature: badSig, publicKey: pubPem, fetchImpl: release(badSig) }, 'SIGNATURE_INVALID');
  await refused('no pinned key', { signature: goodSig, publicKey: '', fetchImpl: release(goodSig) }, 'NO_PUBLIC_KEY');
  await refused('tarball swap', { signature: goodSig, publicKey: pubPem, fetchImpl: release(goodSig, Buffer.from('other-bytes')) }, 'CHECKSUM_MISMATCH');
  await refused('unsigned downgrade while a key is pinned', { publicKey: pubPem, fetchImpl: release(goodSig) }, 'SIGNATURE_REQUIRED');
});

// ---------------------------------------------------------------- runtime end-to-end
test('runtime: in strict mode an unsigned delete over the real WebSocket is refused and nothing is wiped', async () => {
  const { startFakeServer } = require('../../test-support/fakeServer');
  const { createAgentRuntime } = require('../../src/runtime');
  const server = await startFakeServer({ validTokens: ['valid'], monitorConfig: { source: 'proc' } });
  const calls = { wipe: 0, remove: 0 };
  const runtime = createAgentRuntime({
    config: { serverUrl: server.url, heartbeatMs: 10000, backoff: { baseMs: 30, maxMs: 120, factor: 2 } },
    token: 'valid', agentId: 1, logger: silentLogger,
    hsflowdManager: { enable: async () => ({ state: 'active' }), disable: async () => ({ state: 'inactive' }), status: async () => ({ state: 'unknown' }) },
    selfDeleter: { wipeToken: () => { calls.wipe += 1; }, remove: () => { calls.remove += 1; } },
    capabilities: { sources: ['proc'], agentVersion: '0.2.0', managed: 'systemd' }, strictCommands: true,
  });
  const withTimeout = (p, ms, m) => { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(m)), ms); t.unref(); })]).finally(() => clearTimeout(t)); };
  try {
    const reported = server.waitForWsMessage((m) => m.type === 'action-result' && m.action === 'delete');
    runtime.start();
    await withTimeout(new Promise((r) => runtime.once('config', r)), 4000, 'no config');
    server.sendCommandToAll({ name: 'delete', id: 'd1', auditId: 77 });
    const msg = await withTimeout(reported, 4000, 'no delete action-result');
    assert.equal(msg.ok, false);
    assert.match(msg.detail, /signed/);
    assert.deepEqual(calls, { wipe: 0, remove: 0 });
  } finally {
    runtime.stop();
    await server.close();
  }
});

// ---------------------------------------------------------------- repo hygiene
test('no private keys, tokens or real fingerprints are committed; the example config carries no credentials', () => {
  let files;
  try { files = execSync('git ls-files', { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean); } catch { return; }
  const offenders = [];
  for (const f of files) {
    if (!/\.(js|json|sh|ps1|md|yml|yaml|env|example|service|conf)$/.test(f)) continue;
    if (/^(test|test-support)\//.test(f) || /vector\.json$/.test(f)) continue;
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    if (/-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(text)) offenders.push(`${f}: private key`);
    if (/(ghp|github_pat)_[A-Za-z0-9_]{20,}/.test(text)) offenders.push(`${f}: GitHub token`);
  }
  assert.deepEqual(offenders, []);
  const example = JSON.parse(fs.readFileSync(path.join(ROOT, 'config.example.json'), 'utf8'));
  assert.equal(example.token, undefined, 'config.example.json ships a token');
  assert.ok(!example.enrollmentCode || /paste|example|your|<|>/i.test(example.enrollmentCode), 'config.example.json ships a real-looking enrollment code');
  assert.equal(example.serverCertFingerprint, '', 'the example must not pin a real certificate');
  assert.match(fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8'), /\.blueeye-agent|token/, 'the token directory must be git-ignored');
});
