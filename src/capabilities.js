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
} = {}) {
  const sources = [];
  if (canReadProc()) sources.push('proc');
  if (hasSnmp()) sources.push('snmp');
  if (hasNetflow()) sources.push('netflow');
  if (hasSflow()) sources.push('sflow');
  return { sources, agentVersion: version };
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

module.exports = { detectCapabilities };
