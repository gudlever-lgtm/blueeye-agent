'use strict';

const fs = require('fs');

// Detects what this agent can do, so the server can offer only the sources that
// actually work here:
//   - 'proc': /proc/net/dev is readable (Linux host / on-device Linux).
//   - 'snmp': the `net-snmp` module is installed (poll a device's
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
  if (hasSnmp()) sources.push('snmp'); else unavailable.snmp = 'net-snmp is missing — reinstall the agent, or run npm install in its directory';
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

// Which service managers can restart this agent onto new code. Docker rebuilds
// the image instead, and nothing restarts an unmanaged process, so those two are
// the ones a one-click update has to decline.
//
// 'scheduled-task' is the Windows installer's actual supervisor. It writes a
// Scheduled Task rather than a service, because a real Windows service needs a
// service wrapper the agent does not ship — and because the task needed no extra
// dependency it was tagged 'unmanaged', which made every Windows agent in the
// field decline the one-click update and left `/enroll/update.ps1` as the only
// way to move one. A task CAN be stopped and started (schtasks /End, /Run), so
// 'unmanaged' was understating what the host can do, and the whole fleet paid
// for it by being updated through a downloaded script instead of the signed,
// command-authenticated channel that already existed.
const SELF_UPDATABLE = ['systemd', 'windows-service', 'scheduled-task', 'launchd'];
const RUNTIMES = [...SELF_UPDATABLE, 'docker', 'unmanaged'];

// How this agent is supervised, which decides whether it can self-update:
//   - explicit BLUEEYE_RUNTIME (set by the installer) wins;
//   - a Docker container is detected via /.dockerenv or $container;
//   - a systemd service sets $INVOCATION_ID;
//   - a launchd job gets $XPC_SERVICE_NAME (and it is not the placeholder
//     launchd hands an interactive shell);
//   - otherwise 'unmanaged' (a bare `node src/index.js` nothing would restart).
//
// Neither a Windows service nor a Scheduled Task can be detected from the
// environment — the process looks like any other — so there it is the
// installer's BLUEEYE_RUNTIME that says so. Without it a Windows agent reports
// 'unmanaged' and declines updates, which is the old behaviour and the safe one.
function detectManaged({ env = process.env, fileExists = defaultFileExists } = {}) {
  const explicit = String(env.BLUEEYE_RUNTIME || '').toLowerCase();
  if (RUNTIMES.includes(explicit)) return explicit;
  if (fileExists('/.dockerenv') || env.container) return 'docker';
  if (env.INVOCATION_ID) return 'systemd';
  const xpc = String(env.XPC_SERVICE_NAME || '');
  if (xpc && xpc !== '0' && !/^com\.apple\.xpc\.launchd\.oneshot/.test(xpc)) return 'launchd';
  return 'unmanaged';
}

// Can the server push code to this agent at all? Used by the update handler and
// reported to the server so the dashboard does not offer what cannot work.
function isSelfUpdatable(managed) {
  return SELF_UPDATABLE.includes(String(managed || '').toLowerCase());
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

module.exports = { SELF_UPDATABLE, isSelfUpdatable, detectCapabilities, detectManaged };
