'use strict';

const fs = require('fs');

// Detects what this agent can do, so the server can offer only the sources that
// actually work here:
//   - 'proc': /proc/net/dev is readable (Linux host / on-device Linux).
//   - 'snmp': the optional `net-snmp` module is installed (poll a device's
//     interface counters over SNMP).
//   - 'netflow': always available — a built-in UDP collector for NetFlow
//     v5/v9/IPFIX flow exports (vendor-neutral; the device must export flows to
//     this agent).
//   - 'sflow': always available — a built-in UDP collector for sFlow v5 sampled
//     exports (Arista/HPE and many switches).
// Detection is injectable for tests.
function detectCapabilities({
  canReadProc = defaultCanReadProc,
  hasSnmp = defaultHasSnmp,
  hasNetflow = () => true,
  hasSflow = () => true,
  version = readVersion(),
  managed = detectManaged(),
} = {}) {
  const sources = [];
  const unavailable = {};
  if (canReadProc()) sources.push('proc'); else unavailable.proc = '/proc/net/dev not readable';
  if (hasSnmp()) sources.push('snmp'); else unavailable.snmp = 'net-snmp not installed (npm install net-snmp)';
  if (hasNetflow()) sources.push('netflow');
  if (hasSflow()) sources.push('sflow');
  // `managed` tells the server how this agent is supervised, so it knows whether
  // a one-click self-update is possible: 'systemd' (yes), 'docker'/'unmanaged'
  // (no — the host rebuilds those).
  //
  // `unavailable` explains WHY an optional source isn't offered (e.g. the
  // optional net-snmp dependency is absent), so the dashboard can surface it
  // instead of SNMP just silently never appearing. Additive + metadata only.
  return { sources, unavailable, agentVersion: version, managed };
}

// How this agent is supervised, which decides whether it can self-update:
//   - explicit BLUEEYE_RUNTIME (set by the installer) wins;
//   - a Docker container is detected via /.dockerenv or $container;
//   - a systemd service sets $INVOCATION_ID;
//   - otherwise 'unmanaged' (a bare `node src/index.js` nothing would restart).
function detectManaged({ env = process.env, fileExists = defaultFileExists } = {}) {
  const explicit = String(env.BLUEEYE_RUNTIME || '').toLowerCase();
  if (explicit === 'docker' || explicit === 'systemd' || explicit === 'unmanaged') return explicit;
  if (fileExists('/.dockerenv') || env.container) return 'docker';
  if (env.INVOCATION_ID) return 'systemd';
  return 'unmanaged';
}

function defaultFileExists(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function defaultCanReadProc() {
  try {
    fs.accessSync('/proc/net/dev', fs.constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function defaultHasSnmp() {
  try {
    require.resolve('net-snmp');
    return true;
  } catch {
    return false;
  }
}

function readVersion() {
  try {
    return require('../package.json').version || 'unknown';
  } catch {
    return 'unknown';
  }
}

module.exports = { detectCapabilities, detectManaged };
