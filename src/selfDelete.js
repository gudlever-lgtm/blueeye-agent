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
function createSelfDeleter({
  installDir = path.join(__dirname, '..'),
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
    const child = spawnImpl(
      'sh',
      ['-c', `sleep 2; SERVICE_NAME='${serviceName}' BLUEEYE_INSTALL_DIR='${installDir}' sh '${uninstallPath}' --yes`],
      { detached: true, stdio: 'ignore' }
    );
    if (child && typeof child.unref === 'function') child.unref();
    return child;
  }

  return { wipeToken, remove };
}

module.exports = { createSelfDeleter };
