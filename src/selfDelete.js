'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// Self-removal for a server-commanded delete. Two steps:
//   1. wipeToken() — overwrite the stored opaque token with random bytes, then
//      unlink it, so it isn't trivially recoverable from freed blocks.
//   2. remove()    — run the shipped uninstall.sh DETACHED (so it outlives this
//      process being stopped), which stops/disables the systemd service and
//      removes the install directory. A short sleep first lets an in-flight WS
//      "completed" frame flush before the service (and thus this process) stops.
// Everything is injectable so the flow is tested without touching the system.
// The install ROOT to remove. Under the versioned layout the service runs from the
// `current` symlink (BLUEEYE_CURRENT_LINK=/opt/blueeye-agent/current), so the root
// is its PARENT — not __dirname/.. (which would be the swappable release dir, e.g.
// releases/<v>). Falls back to the module's parent for a flat/dev layout.
function defaultInstallDir() {
  const link = process.env.BLUEEYE_CURRENT_LINK;
  if (link) return path.dirname(link);
  return path.join(__dirname, '..');
}

function createSelfDeleter({
  installDir = defaultInstallDir(),
  tokenPath = process.env.BLUEEYE_TOKEN_PATH || path.join(__dirname, '..', '.blueeye-agent', 'token'),
  serviceName = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent',
  uninstallPath = path.join(__dirname, '..', 'uninstall.sh'),
  spawnImpl = spawn,
  fsImpl = fs,
  logger = console,
} = {}) {
  function wipeToken() {
    try {
      if (!fsImpl.existsSync(tokenPath)) return;
      let size = 256;
      try { size = fsImpl.statSync(tokenPath).size || 256; } catch { /* default */ }
      fsImpl.writeFileSync(tokenPath, crypto.randomBytes(Math.max(size, 64)), { mode: 0o600 });
      fsImpl.rmSync(tokenPath, { force: true });
    } catch (err) {
      if (logger && typeof logger.warn === 'function') logger.warn(`[delete] token wipe failed: ${err.message}`);
    }
  }

  function remove() {
    // Remove everything: the install root, the state dir (token/config) and the log
    // dir. Derived from the agent's own env so a custom layout still cleans up fully.
    const stateDir = path.dirname(tokenPath);
    const logDir = process.env.BLUEEYE_ACTION_LOG
      ? path.dirname(process.env.BLUEEYE_ACTION_LOG)
      : '/var/log/blueeye-agent';
    const child = spawnImpl(
      'sh',
      ['-c', `sleep 2; SERVICE_NAME='${serviceName}' BLUEEYE_INSTALL_DIR='${installDir}' BLUEEYE_STATE_DIR='${stateDir}' BLUEEYE_LOG_DIR='${logDir}' sh '${uninstallPath}' --yes`],
      { detached: true, stdio: 'ignore' }
    );
    if (child && typeof child.unref === 'function') child.unref();
    return child;
  }

  return { wipeToken, remove };
}

module.exports = { createSelfDeleter };
