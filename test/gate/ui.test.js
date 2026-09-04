'use strict';

// GATE · UI — blueeye-agent operator surface
//
// The agent has no dashboard; its "UI" is the CLI (enroll / doctor / --help),
// the doctor report an operator reads to fix a broken install, and the
// install/uninstall scripts. This suite pins the CLI contract (arguments,
// usage text, exit codes), the doctor report format, and that every shipped
// shell script at least parses.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { parseArgs, USAGE } = require('../../src/cli');
const { runDoctor, formatReport, toWsUrl } = require('../../src/doctor');

const ROOT = path.join(__dirname, '..', '..');
const INDEX = path.join(ROOT, 'src', 'index.js');
const pkg = require('../../package.json');

// ---------------------------------------------------------------- CLI arguments
test('parseArgs: commands, flags, aliases and unknown flags', () => {
  assert.deepEqual(parseArgs(['node', 'x']), { cmd: null, opts: {} });
  assert.deepEqual(parseArgs(['node', 'x', '--help']), { cmd: null, opts: { help: true } });
  assert.deepEqual(parseArgs(['node', 'x', '-h']), { cmd: null, opts: { help: true } });
  assert.equal(parseArgs(['node', 'x', 'doctor']).cmd, 'doctor');
  const e = parseArgs(['node', 'x', 'enroll', '--code', 'C', '--server', 'http://s', '--cert-fingerprint', 'F', '--force']);
  assert.deepEqual(e, { cmd: 'enroll', opts: { code: 'C', server: 'http://s', fingerprint: 'F', force: true } });
  assert.equal(parseArgs(['node', 'x', 'enroll', '--fingerprint', 'Z']).opts.fingerprint, 'Z');
  assert.deepEqual(parseArgs(['node', 'x', 'enroll', '--unknown', 'v']).opts, {}, 'unknown flags are ignored, never crash');
  assert.equal(parseArgs(['node', 'x', 'enroll', '--code']).opts.code, undefined, 'a dangling flag has no value');
});

test('USAGE documents every command and flag the CLI accepts', () => {
  for (const token of ['enroll', 'doctor', '--help', '--code', '--server', '--fingerprint', '--force']) {
    assert.ok(USAGE.includes(token), `USAGE lacks ${token}`);
  }
  assert.ok(USAGE.startsWith('blueeye-agent'));
  assert.ok(USAGE.includes('Usage:'));
  assert.ok(!/\t/.test(USAGE), 'usage text should not mix tabs into terminal output');
});

// ---------------------------------------------------------------- process exit codes
function run(args, env = {}) {
  return spawnSync(process.execPath, [INDEX, ...args], { cwd: ROOT, encoding: 'utf8', timeout: 20000, env: { ...process.env, BLUEEYE_AGENT_CONFIG: path.join(ROOT, 'does-not-exist.json'), ...env } });
}

test('`blueeye-agent --help` prints usage to stdout and exits 0', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes('Usage:'));
  assert.equal(r.stderr.trim(), '');
});

test('`blueeye-agent help` and `-h` behave like --help', () => {
  for (const a of [['help'], ['-h']]) {
    const r = run(a);
    assert.equal(r.status, 0, `${a}: ${r.stderr}`);
    assert.ok(r.stdout.includes('Usage:'));
  }
});

test('an unknown command exits 1 and explains itself on stderr (nothing on stdout)', () => {
  const r = run(['frobnicate']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Unknown command: frobnicate/);
  assert.ok(r.stderr.includes('Usage:'));
  assert.equal(r.stdout.trim(), '');
});

test('`enroll` without a code fails fast with a clear message and exit 1 (no server contact needed)', () => {
  const r = run(['enroll', '--server', 'http://127.0.0.1:9'], { BLUEEYE_SERVER_URL: 'http://127.0.0.1:9' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Missing --code/);
});

// ---------------------------------------------------------------- doctor report
const baseDeps = { lookup: async () => ({ address: '10.0.0.9' }), tcpConnect: async () => {}, tokenReader: () => ({ agentId: 7, token: 'tok' }), timeoutMs: 300 };
const wsThat = (behave) => class { constructor() { this._h = {}; setImmediate(() => behave(this)); } on(ev, cb) { (this._h[ev] = this._h[ev] || []).push(cb); return this; } emit(ev, ...a) { (this._h[ev] || []).forEach((cb) => cb(...a)); } terminate() {} };
const WS_OK = wsThat((ws) => ws.emit('message', JSON.stringify({ type: 'connected' })));
const WS_401 = wsThat((ws) => ws.emit('unexpected-response', {}, { statusCode: 401 }));
const request = (map) => async ({ url }) => { const p = url.replace(/^https?:\/\/[^/]+/, ''); const v = map[p]; if (v instanceof Error) throw v; return v === undefined ? { status: 404, json: null } : v; };

test('doctor: a healthy install reports every check ✓ and CONNECTED (exit 0 semantics)', async () => {
  const report = await runDoctor({ ...baseDeps, config: { serverUrl: 'https://blueeye.example.dk', tokenPath: '/x/token', serverCertFingerprint: '' }, request: request({ '/enroll/config': { status: 200, json: {} }, '/agents/me/config': { status: 200, json: {} } }), WebSocketImpl: WS_OK });
  assert.equal(report.connected, true);
  assert.deepEqual(report.failed, []);
  const text = formatReport(report);
  assert.match(text, /Result: CONNECTED/);
  assert.ok(!text.includes('✗'));
  for (const name of ['config', 'dns', 'tcp']) assert.ok(text.includes(`✓ ${name}`), `report lacks ${name}`);
});

test('doctor: a failing check renders ✗ with a → suggestion and NOT CONNECTED', async () => {
  const report = await runDoctor({ ...baseDeps, config: { serverUrl: 'https://blueeye.example.dk', tokenPath: '/x/token', serverCertFingerprint: '' }, request: request({ '/enroll/config': { status: 200, json: {} }, '/agents/me/config': { status: 401, json: {} } }), WebSocketImpl: WS_401 });
  assert.equal(report.connected, false);
  assert.ok(report.failed.length >= 1);
  const text = formatReport(report);
  assert.match(text, /✗ /);
  assert.match(text, /→ /, 'every failure needs an actionable suggestion');
  assert.match(text, /Result: NOT CONNECTED — \d+ check\(s\) failed/);
  for (const c of report.failed) assert.ok(c.suggestion, `${c.name} failed without a suggestion`);
});

test('doctor: no server URL is a config failure with a suggestion, never a crash', async () => {
  const report = await runDoctor({ ...baseDeps, config: { serverUrl: '', tokenPath: '/x/token' } });
  assert.equal(report.connected, false);
  const cfg = report.checks.find((c) => c.name === 'config');
  assert.equal(cfg.ok, false);
  assert.match(cfg.suggestion, /BLUEEYE_SERVER_URL/);
  assert.doesNotThrow(() => formatReport(report));
});

test('doctor: toWsUrl maps http→ws and https→wss and pins the /ws/agent path', () => {
  assert.equal(toWsUrl('https://srv.example.dk'), 'wss://srv.example.dk/ws/agent');
  assert.equal(toWsUrl('http://srv.example.dk:3000/some/path?x=1'), 'ws://srv.example.dk:3000/ws/agent');
});

// ---------------------------------------------------------------- shipped scripts
test('every shipped shell script parses (bash -n) and refuses to run on errors', () => {
  const scripts = ['install.sh', 'uninstall.sh', ...fs.readdirSync(path.join(ROOT, 'scripts')).filter((f) => f.endsWith('.sh')).map((f) => `scripts/${f}`)];
  const bash = spawnSync('bash', ['--version']);
  if (bash.status !== 0) return; // no bash on this host
  for (const s of scripts) {
    const r = spawnSync('bash', ['-n', path.join(ROOT, s)], { encoding: 'utf8' });
    assert.equal(r.status, 0, `${s}: ${r.stderr}`);
    const text = fs.readFileSync(path.join(ROOT, s), 'utf8');
    assert.match(text, /^#!\/(usr\/bin\/env )?(ba)?sh/, `${s}: missing shebang`);
    // gate.sh handles its own failures (it must report every phase, not stop at the first).
    if (s === 'scripts/gate.sh') assert.match(text, /set -[a-zA-Z]*u[a-zA-Z]* pipefail/, `${s}: needs set -u + pipefail`);
    else assert.match(text, /set -[a-zA-Z]*e/, `${s}: does not exit on error (set -e)`);
  }
});

test('package.json: single runtime dependency (ws), no build step, node >= 18, semver version', () => {
  assert.deepEqual(Object.keys(pkg.dependencies || {}), ['ws']);
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.scripts.test, 'node --test');
  assert.equal(pkg.scripts.build, undefined, 'the agent must stay a no-build CommonJS package');
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.match(pkg.engines.node, />=18/);
});
