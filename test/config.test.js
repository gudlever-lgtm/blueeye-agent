'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { loadConfig, clearEnrollmentCode, configPathFrom, secureUrl } = require('../src/config');

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

  // https://, not http:// — an http server URL is upgraded unless it is
  // loopback or BLUEEYE_ALLOW_HTTP is set (see the HTTPS tests below). The
  // point of this case is that the ENV won over the file, which it still does.
  assert.equal(cfg.serverUrl, 'https://env:2');
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

// ---- HTTPS is the default, whatever the config says -----------------------
// An agent carries a bearer token on every request and a stream of the
// customer's network metadata on its socket. Nobody CHOOSES plain HTTP for
// that — it is inherited: an install script generated before the server had a
// certificate bakes http:// into the launcher, and there it stays until
// somebody edits a file on every host in the fleet.
test('an http:// server URL is upgraded to https, and the port is kept', () => {
  const c = loadConfig({ env: { BLUEEYE_SERVER_URL: 'http://blueeye.kunde.dk' } });
  assert.equal(c.serverUrl, 'https://blueeye.kunde.dk');
  assert.deepEqual(c.upgradedFromHttp, ['http://blueeye.kunde.dk'], 'the host cannot say so in its own log');

  // :3000 was spelled out by somebody. Guessing 443 would break the one
  // deployment that bothered to say which port it listens on.
  assert.equal(loadConfig({ env: { BLUEEYE_SERVER_URL: 'http://blueeye.kunde.dk:3000' } }).serverUrl,
    'https://blueeye.kunde.dk:3000');
});

test('loopback is left alone — that is the dev server, not a deployment', () => {
  for (const url of ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000']) {
    assert.equal(loadConfig({ env: { BLUEEYE_SERVER_URL: url } }).serverUrl, url, url);
  }
});

test('BLUEEYE_ALLOW_HTTP is the way out, and it has to be set deliberately', () => {
  const c = loadConfig({ env: { BLUEEYE_SERVER_URL: 'http://blueeye.intern', BLUEEYE_ALLOW_HTTP: '1' } });
  assert.equal(c.serverUrl, 'http://blueeye.intern');
  assert.equal(c.allowHttp, true);
  assert.deepEqual(c.upgradedFromHttp, []);
  // Not set, not a truthy-looking string: off.
  assert.equal(loadConfig({ env: { BLUEEYE_SERVER_URL: 'http://blueeye.intern', BLUEEYE_ALLOW_HTTP: 'maybe' } }).serverUrl,
    'https://blueeye.intern');
});

test('the spare ingresses are upgraded too — one http fallback is the whole hole', () => {
  const c = loadConfig({
    env: {
      BLUEEYE_SERVER_URL: 'https://blueeye.kunde.dk',
      BLUEEYE_SERVER_URLS: 'http://10.0.0.5:3000, https://spare.kunde.dk',
    },
  });
  assert.deepEqual(c.serverUrls, ['https://blueeye.kunde.dk', 'https://10.0.0.5:3000', 'https://spare.kunde.dk']);
  assert.deepEqual(c.upgradedFromHttp, ['http://10.0.0.5:3000']);
});

test('an https URL and an unparseable one are both left exactly as they are', () => {
  assert.equal(loadConfig({ env: { BLUEEYE_SERVER_URL: 'https://x.dk' } }).serverUrl, 'https://x.dk');
  assert.equal(secureUrl('not a url').url, 'not a url');
  assert.equal(secureUrl('').url, '');
});
