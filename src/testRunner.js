'use strict';

const os = require('os');

// Runs a "test" in response to a server command. For now this is a lightweight,
// always-safe system diagnostic; the result payload is what gets reported back
// to the server. The shape is intentionally generic so the server can store it
// as JSON.
async function runTest(command = {}) {
  const name = (command && (command.name || command.test)) || 'system-check';
  const startedAt = new Date().toISOString();

  const metrics = {
    uptimeSec: Math.round(os.uptime()),
    loadavg: os.loadavg(),
    freeMemBytes: os.freemem(),
    totalMemBytes: os.totalmem(),
    cpuCount: os.cpus().length,
  };

  return {
    name,
    commandId: (command && command.id) ?? null,
    ok: true,
    startedAt,
    finishedAt: new Date().toISOString(),
    metrics,
  };
}

module.exports = { runTest };
