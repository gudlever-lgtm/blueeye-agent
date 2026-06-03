'use strict';

const fs = require('fs');
const path = require('path');
const { parseConfiguredTargets } = require('./probes/targets');
const { normalizeFingerprint } = require('./fingerprint');

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

// Truthy unless explicitly turned off ("0"/"false"/"no"/"off"). env wins over
// the JSON file; falls back to `dflt` when neither is set.
function toBool(envVal, fileVal, dflt) {
  const v = envVal !== undefined ? envVal : fileVal;
  if (v === undefined || v === null || v === '') return dflt;
  if (typeof v === 'boolean') return v;
  return !['0', 'false', 'no', 'off'].includes(String(v).toLowerCase());
}

function configPathFrom(env) {
  return env.BLUEEYE_AGENT_CONFIG || path.join(process.cwd(), 'blueeye-agent.config.json');
}

function readConfigFile(configPath) {
  if (!fs.existsSync(configPath)) return {};
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8')) || {};
  } catch (err) {
    throw new Error(`Failed to parse config file ${configPath}: ${err.message}`);
  }
}

// Loads configuration, merging (lowest to highest precedence):
//   built-in defaults  <  JSON config file  <  environment variables
function loadConfig({ env = process.env } = {}) {
  const configPath = configPathFrom(env);
  const file = readConfigFile(configPath);

  const serverUrl = env.BLUEEYE_SERVER_URL || file.serverUrl || 'http://localhost:3000';
  const enrollmentCode = env.BLUEEYE_ENROLLMENT_CODE || file.enrollmentCode || null;
  // SHA-256 of the server's (or its reverse proxy's) TLS leaf cert. When set and
  // the server is https, the agent pins it and refuses a mismatching cert.
  const serverCertFingerprint = normalizeFingerprint(env.BLUEEYE_SERVER_CERT_FINGERPRINT || file.serverCertFingerprint || '');
  const tokenPath =
    env.BLUEEYE_TOKEN_PATH ||
    file.tokenPath ||
    path.join(path.dirname(configPath), '.blueeye-agent', 'token');
  const heartbeatMs = toInt(env.BLUEEYE_HEARTBEAT_MS, file.heartbeatMs ?? 15000);
  const backoff = {
    baseMs: toInt(env.BLUEEYE_RECONNECT_BASE_MS, file.reconnectBaseMs ?? 1000),
    maxMs: toInt(env.BLUEEYE_RECONNECT_MAX_MS, file.reconnectMaxMs ?? 30000),
    factor: 2,
  };

  // Continuous reporting: how often the agent measures and submits traffic on
  // its own (0 disables it; default 60s). The sampling window per measurement
  // is reportSampleMs.
  const reportIntervalMs = toInt(env.BLUEEYE_REPORT_INTERVAL_MS, file.reportIntervalMs ?? 60000);
  const reportSampleMs = toInt(env.BLUEEYE_REPORT_SAMPLE_MS, file.reportSampleMs ?? 1000);

  // Scheduled active probes: the agent periodically pings its default gateway +
  // DNS servers (auto-discovered) and any configured targets, so fleet health is
  // populated without anyone triggering a probe. 0 disables it (default 60s).
  // Metadata only: reachability/timings, never payload.
  const probeIntervalMs = toInt(env.BLUEEYE_PROBE_INTERVAL_MS, file.probeIntervalMs ?? 60000);
  const probeCount = toInt(env.BLUEEYE_PROBE_COUNT, file.probeCount ?? 3);
  const probeAutoGateway = toBool(env.BLUEEYE_PROBE_GATEWAY, file.probeGateway, true);
  const probeAutoDns = toBool(env.BLUEEYE_PROBE_DNS, file.probeDns, true);
  const probeTargets = parseConfiguredTargets(env.BLUEEYE_PROBE_TARGETS ?? file.probeTargets);

  return {
    configPath,
    serverUrl,
    enrollmentCode,
    serverCertFingerprint,
    tokenPath,
    heartbeatMs,
    backoff,
    reportIntervalMs,
    reportSampleMs,
    probeIntervalMs,
    probeCount,
    probeAutoGateway,
    probeAutoDns,
    probeTargets,
  };
}

// Removes `enrollmentCode` from the JSON config file so the one-time code is
// not reused or left on disk. No-op when there is no config file or no code.
// (If the code was supplied purely via an env var it cannot be unset here — but
// once a token is stored the agent never enrolls again.)
function clearEnrollmentCode(config) {
  const { configPath } = config;
  if (!configPath || !fs.existsSync(configPath)) return false;
  const file = readConfigFile(configPath);
  if (!('enrollmentCode' in file)) return false;
  delete file.enrollmentCode;
  fs.writeFileSync(configPath, `${JSON.stringify(file, null, 2)}\n`);
  return true;
}

// Persists embedded server settings (serverUrl + cert fingerprint) into the
// JSON config file after enrollment, so the long-running service reaches the
// right server with pinning — the user never types the URL. Only writes keys
// with a value; creates the file if needed.
function writeConfigValues(config, values = {}) {
  const { configPath } = config;
  if (!configPath) return false;
  let file = {};
  if (fs.existsSync(configPath)) file = readConfigFile(configPath);
  let changed = false;
  for (const [k, v] of Object.entries(values)) {
    if (v === undefined || v === null || v === '') continue;
    if (file[k] !== v) { file[k] = v; changed = true; }
  }
  if (!changed && fs.existsSync(configPath)) return false;
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, `${JSON.stringify(file, null, 2)}\n`);
  return true;
}

module.exports = { loadConfig, clearEnrollmentCode, writeConfigValues };
