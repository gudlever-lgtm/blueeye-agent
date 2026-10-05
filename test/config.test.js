'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadConfig, clearEnrollmentCode, configPathFrom } = require('../src/config');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-agent-cfg-'));
}

test('loadConfig merges file then env (env wins)', () => {
  const configPath = path.join(tmpDir(), 'config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify({ serverUrl: 'http://file:1', enrollmentCode: 'fc', tokenPath: '/t/tok', heartbeatMs: 5000 })
  );

  const cfg = loadConfig({
    env: { BLUEEYE_AGENT_CONFIG: configPath, BLUEEYE_SERVER_URL: 'http://env:2' },
  });

  assert.equal(cfg.serverUrl, 'http://env:2'); // env overrides file
  assert.equal(cfg.enrollmentCode, 'fc'); // from file
  assert.equal(cfg.tokenPath, '/t/tok'); // from file
  assert.equal(cfg.heartbeatMs, 5000);
});

test('loadConfig falls back to defaults without a file', () => {
  const configPath = path.join(tmpDir(), 'absent.json');
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } });

  assert.equal(cfg.serverUrl, 'http://localhost:3000');
  assert.equal(cfg.enrollmentCode, null);
  assert.ok(cfg.tokenPath.endsWith(path.join('.blueeye-agent', 'token')));
  assert.equal(cfg.backoff.factor, 2);
});

test('config path defaults to the install dir and ignores process.cwd()', () => {
  // Resolves next to the agent package root (src/..) — the same base tokenPath
  // uses — never the caller's cwd.
  const expected = path.join(__dirname, '..', 'blueeye-agent.config.json');
  assert.equal(configPathFrom({}), expected);

  // The enroll one-shot runs without cd-ing into the install dir, so changing cwd
  // must not move the config path (and must not throw the way a deleted cwd would).
  const orig = process.cwd();
  const tmp = tmpDir();
  try {
    process.chdir(tmp);
    assert.equal(configPathFrom({}), expected);
  } finally {
    process.chdir(orig);
  }

  // An explicit override still wins.
  assert.equal(configPathFrom({ BLUEEYE_AGENT_CONFIG: '/etc/be.json' }), '/etc/be.json');
});

test('clearEnrollmentCode removes only the code, preserving other fields', () => {
  const configPath = path.join(tmpDir(), 'config.json');
  fs.writeFileSync(
    configPath,
    JSON.stringify({ serverUrl: 'http://x', enrollmentCode: 'secret', tokenPath: '/t' })
  );
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } });

  assert.equal(clearEnrollmentCode(cfg), true);

  const after = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal('enrollmentCode' in after, false);
  assert.equal(after.serverUrl, 'http://x');
  assert.equal(after.tokenPath, '/t');
});

test('clearEnrollmentCode is a no-op when there is no config file', () => {
  const cfg = loadConfig({ env: { BLUEEYE_AGENT_CONFIG: path.join(tmpDir(), 'none.json') } });
  assert.equal(clearEnrollmentCode(cfg), false);
});

test('capabilitiesIntervalMs: 300 s by default, file then env, 0 disables', () => {
  const dir = tmpDir();
  const absent = path.join(dir, 'absent.json');
  assert.equal(loadConfig({ env: { BLUEEYE_AGENT_CONFIG: absent } }).capabilitiesIntervalMs, 300000);

  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ capabilitiesIntervalMs: 60000 }));
  assert.equal(loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } }).capabilitiesIntervalMs, 60000);
  assert.equal(
    loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath, BLUEEYE_CAPABILITIES_INTERVAL_MS: '0' } }).capabilitiesIntervalMs,
    0,
  );
});

test('configRefreshIntervalMs: 300 s by default, file then env, 0 disables', () => {
  const dir = tmpDir();
  const absent = path.join(dir, 'absent.json');
  assert.equal(loadConfig({ env: { BLUEEYE_AGENT_CONFIG: absent } }).configRefreshIntervalMs, 300000);

  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ configRefreshIntervalMs: 60000 }));
  assert.equal(loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath } }).configRefreshIntervalMs, 60000);
  assert.equal(
    loadConfig({ env: { BLUEEYE_AGENT_CONFIG: configPath, BLUEEYE_CONFIG_REFRESH_MS: '0' } }).configRefreshIntervalMs,
    0,
  );
});

// ---- Finding an installed agent's own config from a plain prompt -----------
// The service gets BLUEEYE_AGENT_CONFIG and BLUEEYE_TOKEN_PATH from its
// launcher (run-agent.cmd on Windows, the systemd unit on Linux). A PERSON
// opening a prompt to run `blueeye-agent doctor` gets neither — and doctor then
// read no config and no token, and reported "Server URL: http://localhost:3000"
// and "not enrolled" about a host that was enrolled and reconnecting every
// twenty seconds. The defaults look in the install location too.
test('the Windows install location is searched when nothing names a config', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-pd-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const agentDir = path.join(dir, 'BlueEyes', 'agent');
  fs.mkdirSync(agentDir, { recursive: true });
  fs.writeFileSync(path.join(agentDir, 'blueeye-agent.config.json'),
    JSON.stringify({ serverUrl: 'https://blueeye.example.dk' }));

  const cfg = loadConfig({ env: { ProgramData: dir }, platform: 'win32' });
  assert.equal(cfg.serverUrl, 'https://blueeye.example.dk',
    'the installed config was not found, so doctor diagnoses the defaults');
});

// ...under the name the INSTALLER writes, which is the half that was missed.
// install.sh and install.ps1 both write `config.json` into the state directory
// (`/var/lib/blueeye-agent`, `C:\\ProgramData\\BlueEyes\\state`) — never
// `blueeye-agent.config.json`, which is the flat-checkout name. Searching the
// right directories for a file name that is never in them found nothing, so
// doctor still reported localhost:3000 about an enrolled host.
test('the installed config is found under the name the installer writes', (t) => {
  for (const [platform, envFor, stateDir] of [
    ['win32', (dir) => ({ ProgramData: dir }), (dir) => path.join(dir, 'BlueEyes', 'state')],
    ['linux', () => ({}), null],
  ]) {
    if (!stateDir) continue; // the linux state dir is absolute and not writable in a test
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-pd-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const state = stateDir(dir);
    fs.mkdirSync(state, { recursive: true });
    fs.writeFileSync(path.join(state, 'config.json'), JSON.stringify({ serverUrl: 'https://blueeye.example.dk' }));

    const cfg = loadConfig({ env: envFor(dir), platform });
    assert.equal(cfg.serverUrl, 'https://blueeye.example.dk',
      `${platform}: the installed config.json was not found, so doctor diagnoses the defaults`);
  }
});

// A host that has both keeps using the one it used before: the long name in the
// state dir is what a hand-written config is called, and renaming somebody's
// configuration out from under them by changing a search order is not a fix.
test('the long name wins over config.json in the same directory', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-pd-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const state = path.join(dir, 'BlueEyes', 'state');
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(state, 'blueeye-agent.config.json'), JSON.stringify({ serverUrl: 'https://long.example' }));
  fs.writeFileSync(path.join(state, 'config.json'), JSON.stringify({ serverUrl: 'https://short.example' }));

  assert.equal(loadConfig({ env: { ProgramData: dir }, platform: 'win32' }).serverUrl, 'https://long.example');
});

test('an explicit BLUEEYE_AGENT_CONFIG still wins over the install location', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blueeye-pd-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const agentDir = path.join(dir, 'BlueEyes', 'agent');
  fs.mkdirSync(agentDir, { recursive: true });
  fs.writeFileSync(path.join(agentDir, 'blueeye-agent.config.json'), JSON.stringify({ serverUrl: 'https://wrong.example' }));
  const explicit = path.join(dir, 'explicit.json');
  fs.writeFileSync(explicit, JSON.stringify({ serverUrl: 'https://right.example' }));

  const cfg = loadConfig({ env: { ProgramData: dir, BLUEEYE_AGENT_CONFIG: explicit }, platform: 'win32' });
  assert.equal(cfg.serverUrl, 'https://right.example');
});
