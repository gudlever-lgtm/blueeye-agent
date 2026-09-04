'use strict';

// GATE · VALIDATION — blueeye-agent
//
// The agent trusts nothing it is handed: not its own config file, not the
// environment, not the commands the server pushes. This suite pins how
// config values are coerced and defaulted, how probe targets are parsed
// (invalid ones dropped, never crashing the agent), that every command
// recogniser rejects malformed commands without throwing, and that the wire
// contract constants stay sane.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadConfig, clearEnrollmentCode, writeConfigValues, configPathFrom } = require('../../src/config');
const { parseConfiguredTargets, gatewayFromProcRoute } = require('../../src/probes/targets');
const command = require('../../src/command');
const { normalizeFingerprint } = require('../../src/fingerprint');
const { PROTOCOL_VERSION } = require('../../src/protocol');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-gate-'));
const GARBAGE = [undefined, null, '', 'str', 0, -1, 1.5, NaN, true, [], {}, () => {}, Symbol('s'), { name: 42 }, { name: null }];

// ---------------------------------------------------------------- config
test('loadConfig: defaults are safe; env beats file beats defaults; numbers/booleans are coerced, garbage falls back', () => {
  const dir = tmp();
  const configPath = path.join(dir, 'c.json');
  fs.writeFileSync(configPath, JSON.stringify({ serverUrl: 'http://file', heartbeatMs: 5000, probeGateway: false, probeTargets: 'ping:1.1.1.1' }));
  const fromFile = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } });
  assert.equal(fromFile.serverUrl, 'http://file');
  assert.equal(fromFile.heartbeatMs, 5000);
  assert.equal(fromFile.probeAutoGateway, false);
  assert.deepEqual(fromFile.probeTargets, [{ type: 'ping', host: '1.1.1.1' }]);

  const fromEnv = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath, BLUEEYE_SERVER_URL: 'https://env', BLUEEYE_HEARTBEAT_MS: 'abc', BLUEEYE_PROBE_GATEWAY: 'off', BLUEEYE_REPORT_INTERVAL_MS: '-5', BLUEEYE_PROBE_TARGETS: 'tcp:host:99999,dns:example.com' } });
  assert.equal(fromEnv.serverUrl, 'https://env');
  assert.equal(fromEnv.heartbeatMs, 5000, 'a non-numeric env value falls back to the file/default');
  assert.equal(fromEnv.probeAutoGateway, false);
  assert.deepEqual(fromEnv.probeTargets, [{ type: 'dns', host: 'example.com' }], 'the invalid tcp target is dropped');

  const defaults = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: path.join(dir, 'missing.json') } });
  assert.equal(defaults.serverUrl, 'http://localhost:3000');
  assert.equal(defaults.enrollmentCode, null);
  assert.equal(defaults.serverCertFingerprint, '');
  assert.ok(defaults.heartbeatMs > 0 && defaults.reportIntervalMs >= 0 && defaults.probeIntervalMs >= 0);
  assert.ok(defaults.backoff.baseMs > 0 && defaults.backoff.maxMs >= defaults.backoff.baseMs && defaults.backoff.factor > 1);
  assert.ok(path.isAbsolute(defaults.tokenPath));
  assert.deepEqual(defaults.probeTargets, []);
});

test('loadConfig: a corrupt config file fails loudly with the path in the message', () => {
  const dir = tmp();
  const configPath = path.join(dir, 'bad.json');
  fs.writeFileSync(configPath, '{ not json');
  assert.throws(() => loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } }), (e) => e.message.includes('Failed to parse config file') && e.message.includes(configPath));
});

test('configPathFrom ignores process.cwd(); clearEnrollmentCode only removes the code; writeConfigValues skips empty values', () => {
  assert.ok(path.isAbsolute(configPathFrom({})));
  assert.ok(!configPathFrom({}).startsWith(process.cwd()) || configPathFrom({}).startsWith(path.join(__dirname, '..', '..')));
  assert.equal(configPathFrom({ BLUEEYE_AGENT_CONFIG: '/etc/x.json' }), '/etc/x.json');
  const dir = tmp();
  const configPath = path.join(dir, 'c.json');
  fs.writeFileSync(configPath, JSON.stringify({ serverUrl: 'http://s', enrollmentCode: 'ONE-TIME', keep: 1 }));
  assert.equal(clearEnrollmentCode({ configPath }), true);
  assert.deepEqual(JSON.parse(fs.readFileSync(configPath, 'utf8')), { serverUrl: 'http://s', keep: 1 });
  assert.equal(clearEnrollmentCode({ configPath }), false, 'idempotent');
  assert.equal(writeConfigValues({ configPath }, { serverCertFingerprint: '', serverUrl: null }), false, 'empty values are not written');
  assert.equal(writeConfigValues({ configPath }, { serverCertFingerprint: 'AA:BB' }), true);
  assert.equal(JSON.parse(fs.readFileSync(configPath, 'utf8')).serverCertFingerprint, 'AA:BB');
  assert.equal(writeConfigValues({ configPath: '' }, { serverUrl: 'x' }), false);
});

// ---------------------------------------------------------------- probe targets
test('parseConfiguredTargets: every documented form parses, invalid entries are dropped, garbage never throws', () => {
  assert.deepEqual(parseConfiguredTargets('1.1.1.1, ping:8.8.8.8 ,tcp:host:443,dns:example.com,host2:22'), [
    { type: 'ping', host: '1.1.1.1' }, { type: 'ping', host: '8.8.8.8' }, { type: 'tcp', host: 'host', port: 443 }, { type: 'dns', host: 'example.com' }, { type: 'tcp', host: 'host2', port: 22 },
  ]);
  assert.deepEqual(parseConfiguredTargets('tcp:2606:4700::1111:443'), [{ type: 'tcp', host: '2606:4700::1111', port: 443 }]);
  assert.deepEqual(parseConfiguredTargets('[2606:4700::1111]'), [{ type: 'ping', host: '2606:4700::1111' }]);
  assert.deepEqual(parseConfiguredTargets([{ type: 'tcp', host: 'h', port: 80 }, 'dns:x.dk', { host: '' }, 42, null]), [{ type: 'tcp', host: 'h', port: 80 }, { type: 'dns', host: 'x.dk' }]);
  for (const bad of ['tcp:host', 'tcp:host:0', 'tcp:host:65536', 'tcp:host:abc', 'ping:', ':', ',,,']) {
    assert.deepEqual(parseConfiguredTargets(bad), [], `accepted ${JSON.stringify(bad)}`);
  }
  for (const g of GARBAGE) assert.doesNotThrow(() => parseConfiguredTargets(g), String(typeof g));
  assert.deepEqual(parseConfiguredTargets({}), []);
});

test('gatewayFromProcRoute: decodes the default route and ignores malformed rows', () => {
  const table = 'Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0100A8C0\t0003\neth0\t0000A8C0\t00000000\t0001\n';
  assert.equal(gatewayFromProcRoute(table), '192.168.0.1');
  assert.equal(gatewayFromProcRoute('garbage\n\n'), null);
  assert.equal(gatewayFromProcRoute(''), null);
  assert.doesNotThrow(() => gatewayFromProcRoute(undefined));
});

// ---------------------------------------------------------------- server commands
test('command recognisers: canonical + spelling variants are recognised; wrong verbs and missing payloads are not; garbage never throws', () => {
  const cases = [
    ['isRunTestCommand', ['run-test', 'run test', 'RUN_TEST', { name: 'run-test' }, { action: 'run-test' }, { type: 'run-test' }], ['run', 'test', { name: 'run-probe' }]],
    ['isRunProbeCommand', [{ name: 'run-probe', probe: { type: 'ping', host: 'x' } }], ['run-probe', { name: 'run-probe' }, { name: 'run-probe', probe: null }, { name: 'run-probe', probe: 'ping' }]],
    ['isPingCommand', ['ping', { name: 'PING' }], ['pong', { name: 'ping-all' }]],
    ['isUpdateCommand', ['update', 'self-update', 'upgrade', { name: 'self_update' }], ['updates', 'downgrade']],
    ['isSpeedtestCommand', ['speedtest', 'speed-test', { name: 'speed_test' }], ['speed']],
    ['isDiagnoseCommand', ['diagnose', 'diag', 'doctor', 'health-check', 'self check'], ['diagnosis', 'heal']],
    ['isDeleteCommand', ['delete', 'self-delete', 'uninstall'], ['remove', 'rm', 'delete-all']],
    ['isInstallToolCommand', [{ name: 'install-tool', tool: 'traceroute' }], ['install-tool', { name: 'install-tool' }, { name: 'install-tool', tool: '' }, { name: 'install-tool', tool: 42 }]],
    ['isEvidenceCommand', ['evidence', 'evidence-snapshot', { name: 'evidence_snapshot' }], ['evident', 'snapshot']],
    ['isRunDiscoveryCommand', [{ name: 'run-discovery', discovery: {} }, { name: 'sweep', discovery: { cidrs: [] } }], ['run-discovery', { name: 'run-discovery' }, { name: 'run-discovery', discovery: 'all' }]],
  ];
  for (const [fn, yes, no] of cases) {
    assert.equal(typeof command[fn], 'function', fn);
    for (const c of yes) assert.equal(command[fn](c), true, `${fn} should accept ${JSON.stringify(c)}`);
    for (const c of no) assert.equal(command[fn](c), false, `${fn} should reject ${JSON.stringify(c)}`);
    for (const g of GARBAGE) assert.doesNotThrow(() => command[fn](g), `${fn} throws on ${String(typeof g)}`);
    for (const g of [undefined, null, '', 0, [], {}, () => {}]) assert.equal(command[fn](g), false, `${fn} accepted ${JSON.stringify(g)}`);
  }
  const exported = Object.keys(command).sort();
  assert.deepEqual(exported, cases.map((c) => c[0]).sort(), 'a new recogniser needs a gate case');
});

test('no verb is recognised by two different recognisers', () => {
  const verbs = ['run-test', 'run-probe', 'ping', 'update', 'speedtest', 'diagnose', 'delete', 'install-tool', 'evidence', 'run-discovery'];
  for (const v of verbs) {
    const full = { name: v, probe: { type: 'ping' }, tool: 't', discovery: {} };
    const hits = Object.entries(command).filter(([, fn]) => fn(full)).map(([n]) => n);
    assert.equal(hits.length, 1, `${v} matched ${hits.join(', ')}`);
  }
});

// ---------------------------------------------------------------- wire contract
test('normalizeFingerprint accepts the documented spellings and rejects everything else', () => {
  const hex = 'ab'.repeat(32);
  const want = 'AB:'.repeat(31) + 'AB';
  for (const s of [hex, hex.toUpperCase(), 'ab:'.repeat(31) + 'ab', `sha256:${hex}`, `SHA-256 ${hex}`, ` ${hex} `]) assert.equal(normalizeFingerprint(s), want, s);
  for (const s of ['', null, undefined, 'ab', hex.slice(0, 62), `${hex}ab`, 42, {}]) assert.equal(normalizeFingerprint(s), '', String(s));
});

test('PROTOCOL_VERSION is a positive integer and package version is semver', () => {
  assert.ok(Number.isInteger(PROTOCOL_VERSION) && PROTOCOL_VERSION >= 1);
  assert.match(require('../../package.json').version, /^\d+\.\d+\.\d+$/);
});
