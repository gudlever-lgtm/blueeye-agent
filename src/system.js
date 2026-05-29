'use strict';

const os = require('os');

// The agent-reported facts sent at enrollment.
function collectSystemInfo() {
  return {
    hostname: os.hostname(),
    platform: process.platform, // e.g. 'linux', 'win32', 'darwin'
    arch: process.arch, // e.g. 'x64', 'arm64'
  };
}

module.exports = { collectSystemInfo };
