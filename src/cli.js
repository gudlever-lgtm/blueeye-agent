'use strict';

const { enroll } = require('./enroll');
const { readToken, saveToken } = require('./tokenStore');
const { clearEnrollmentCode, writeConfigValues } = require('./config');
const { normalizeFingerprint } = require('./fingerprint');
const { requestJson, makePinnedFetch } = require('./httpsClient');

// Parses argv (the full process.argv). The first non-flag token is the command
// (e.g. "enroll"); the rest are --flag value pairs.
function parseArgs(argv) {
  const args = argv.slice(2);
  const cmd = args.length && !args[0].startsWith('-') ? args[0] : null;
  const opts = {};
  for (let i = cmd ? 1 : 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--code') opts.code = args[++i];
    else if (a === '--server') opts.server = args[++i];
    else if (a === '--fingerprint' || a === '--cert-fingerprint') opts.fingerprint = args[++i];
    else if (a === '--force') opts.force = true;
    else if (a === '--help' || a === '-h') opts.help = true;
  }
  return { cmd, opts };
}

const USAGE = `blueeye-agent — BlueEye monitoring agent

Usage:
  blueeye-agent                      run the agent (uses the stored token)
  blueeye-agent enroll --code <CODE> [--server <URL>] [--fingerprint <SHA256>] [--force]
  blueeye-agent doctor               test connectivity to the server and suggest fixes
  blueeye-agent --help

The enroll command exchanges a one-time code for a permanent token and stores it.
The doctor command checks config, DNS, TCP, HTTP, token auth and the WebSocket,
printing a concrete suggestion for anything that fails (exit 0 = connected).
Server URL and certificate fingerprint are remembered, so the service started
afterwards reaches the right server with certificate pinning.`;

function codedError(message, code, extra = {}) {
  const err = new Error(message);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

// Runs `blueeye-agent enroll`: exchanges the code for a token, pins the server
// certificate, and persists the embedded server settings. Idempotent: with a
// token already stored it does nothing (unless --force). Throws on failure
// WITHOUT writing a token.
async function runEnroll({ opts, config, systemInfo, logger, fetchImpl, requestImpl = requestJson }) {
  const serverUrl = String(opts.server || config.serverUrl || '').replace(/\/+$/, '');
  if (!serverUrl) throw codedError('No server URL — pass --server or set BLUEEYE_SERVER_URL.', 'NO_SERVER');
  if (!opts.code) throw codedError('Missing --code (the enrollment code).', 'NO_CODE');

  // Idempotent: don't re-enroll a machine that already has a token.
  const existing = readToken(config.tokenPath);
  if (existing && !opts.force) {
    logger.info(`Already enrolled as agent ${existing.agentId}; nothing to do (use --force to re-enroll).`);
    return { ok: true, already: true, agentId: existing.agentId };
  }

  const isHttps = /^https:/i.test(serverUrl);
  let fingerprint = normalizeFingerprint(opts.fingerprint || config.serverCertFingerprint || '');

  // If we have no fingerprint but the server is https, discover it from
  // /enroll/config (trust-on-first-use). The embedded fingerprint (install.sh /
  // --fingerprint) is the strong path; this is the convenience fallback.
  if (!fingerprint && isHttps) {
    try {
      const res = await requestImpl({ url: `${serverUrl}/enroll/config` });
      const fp = res && res.json && res.json.certFingerprint;
      if (fp) {
        fingerprint = normalizeFingerprint(fp);
        if (fingerprint) {
          logger.warn('Pinning fingerprint discovered via /enroll/config (trust-on-first-use). For stronger security pass --fingerprint or set BLUEEYE_SERVER_CERT_FINGERPRINT.');
        }
      }
    } catch { /* best-effort — proceed without discovery */ }
  }

  const effectiveFetch = fetchImpl || (isHttps && fingerprint ? makePinnedFetch(fingerprint) : fetch);
  const result = await enroll({ serverUrl, code: opts.code, systemInfo, fetchImpl: effectiveFetch });
  if (!result.ok) {
    throw codedError(`Enrollment rejected by server (HTTP ${result.status ?? '?'}).`, 'ENROLL_FAILED', { detail: result.detail });
  }

  // Only now — after a confirmed success — persist anything.
  saveToken(config.tokenPath, { agentId: result.agentId, token: result.token });
  writeConfigValues(config, { serverUrl, serverCertFingerprint: fingerprint });
  clearEnrollmentCode(config);
  logger.info(`Enrolled as agent ${result.agentId}. Token stored at ${config.tokenPath}.`);
  if (fingerprint) logger.info(`Server certificate pinned (${fingerprint.slice(0, 17)}…).`);
  return { ok: true, agentId: result.agentId, fingerprintPinned: Boolean(fingerprint) };
}

module.exports = { parseArgs, runEnroll, USAGE };
