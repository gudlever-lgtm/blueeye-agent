'use strict';

const { readToken, saveToken } = require('./tokenStore');
const { clearEnrollmentCode } = require('./config');
const { enroll } = require('./enroll');

// Returns usable credentials { agentId, token }:
//   - if a token is already stored, use it (enrollment is skipped entirely);
//   - otherwise enroll with the configured one-time code, store the token with
//     restrictive permissions and clear the code from the config file.
// Throws (without retrying) when there is no way to obtain a token.
async function ensureToken({ config, systemInfo, logger, fetchImpl = fetch }) {
  const existing = readToken(config.tokenPath);
  if (existing) {
    logger.info(`Using stored token for agent ${existing.agentId} (skipping enrollment).`);
    return existing;
  }

  if (!config.enrollmentCode) {
    const err = new Error(
      'No stored token and no enrollmentCode configured — cannot enroll.'
    );
    err.code = 'NO_CREDENTIALS';
    throw err;
  }

  logger.info('No stored token found; enrolling with the server...');
  const result = await enroll({
    serverUrl: config.serverUrl,
    code: config.enrollmentCode,
    systemInfo,
    fetchImpl,
  });

  if (!result.ok) {
    const err = new Error(`Enrollment rejected by server (HTTP ${result.status ?? '?'}).`);
    err.code = 'ENROLL_FAILED';
    err.detail = result.detail;
    throw err;
  }

  saveToken(config.tokenPath, { agentId: result.agentId, token: result.token });
  clearEnrollmentCode(config);
  logger.info(`Enrolled as agent ${result.agentId}; token stored at ${config.tokenPath}.`);
  return { agentId: result.agentId, token: result.token };
}

module.exports = { ensureToken };
