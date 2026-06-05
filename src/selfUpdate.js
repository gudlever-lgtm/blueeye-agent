'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

// Self-update for Node/systemd-managed agents. Given the server URL + token and
// the expected SHA-256 of the published source bundle, it:
//   1. downloads $serverUrl/enroll/agent-source.tgz (authenticated),
//   2. verifies the SHA-256 (ABORTS on mismatch — never installs unverified code),
//   3. extracts it over the install dir (the bundle excludes the token, config,
//      .env and node_modules, so local state is preserved),
//   4. refreshes dependencies (npm ci --omit=dev, falling back to npm install),
//   5. asks systemd to restart this unit onto the new code.
//
// Docker and unmanaged agents are NOT updated here (the host rebuilds those) —
// the caller checks `managed` before invoking. Everything is injectable so the
// flow can be tested without touching the network or the system.
function createSelfUpdater({
  installDir = path.join(__dirname, '..'),
  serviceName = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent',
  exec = spawnSync,
  fsImpl = fs,
  logger = console,
} = {}) {
  function fail(code, message) {
    const err = new Error(message);
    err.code = code;
    return err;
  }

  // Downloads + verifies + installs the new source. Throws (with a `.code`) on
  // any failure; resolves with { ok: true, sha } on success. Does NOT restart —
  // call restart() separately so the result can be acted on first.
  async function update({ serverUrl, token, expectedSha, fetchImpl }) {
    const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
    if (!doFetch) throw fail('NO_FETCH', 'no fetch implementation available');

    const base = String(serverUrl || '').replace(/\/+$/, '');
    const url = `${base}/enroll/agent-source.tgz`;
    logger.info(`[update] downloading ${url}`);
    const res = await doFetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res || !res.ok) throw fail('DOWNLOAD_FAILED', `download failed (HTTP ${res ? res.status : '?'})`);

    const buf = Buffer.from(await res.arrayBuffer());
    const sha = crypto.createHash('sha256').update(buf).digest('hex');
    if (expectedSha && sha !== expectedSha) {
      throw fail('CHECKSUM_MISMATCH', `checksum mismatch (expected ${expectedSha}, got ${sha}) — refusing to install`);
    }
    logger.info(`[update] checksum OK (${sha})`);

    const tmp = fsImpl.mkdtempSync(path.join(os.tmpdir(), 'blueeye-update-'));
    const tgz = path.join(tmp, 'agent-source.tgz');
    fsImpl.writeFileSync(tgz, buf);

    logger.info(`[update] extracting to ${installDir}`);
    let r = exec('tar', ['-xzf', tgz, '-C', installDir], { encoding: 'utf8' });
    if (!r || r.status !== 0) throw fail('EXTRACT_FAILED', `could not extract source: ${(r && (r.stderr || r.error)) || 'unknown error'}`);

    logger.info('[update] installing dependencies (npm ci --omit=dev)');
    r = exec('npm', ['ci', '--omit=dev'], { cwd: installDir, encoding: 'utf8' });
    if (!r || r.status !== 0) {
      r = exec('npm', ['install', '--omit=dev'], { cwd: installDir, encoding: 'utf8' });
      if (!r || r.status !== 0) throw fail('NPM_FAILED', `dependency install failed: ${(r && (r.stderr || r.error)) || 'unknown error'}`);
    }

    try { fsImpl.rmSync(tmp, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
    return { ok: true, sha };
  }

  // Asks systemd to restart this unit. --no-block enqueues the job in PID 1, so
  // it completes even though this process is terminated during the stop phase
  // (systemd then starts a fresh instance running the just-installed code).
  function restart() {
    logger.info(`[update] requesting restart of ${serviceName}`);
    return exec('systemctl', ['--no-block', 'restart', serviceName], { encoding: 'utf8' });
  }

  return { update, restart };
}

module.exports = { createSelfUpdater };
