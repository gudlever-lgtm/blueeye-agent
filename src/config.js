'use strict';

const fs = require('fs');
const path = require('path');

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
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

  return { configPath, serverUrl, enrollmentCode, tokenPath, heartbeatMs, backoff };
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

module.exports = { loadConfig, clearEnrollmentCode };
