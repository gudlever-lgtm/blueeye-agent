'use strict';

const { sampleTraffic } = require('./trafficMonitor');

// Runs a "test" in response to a server command. The test measures real network
// traffic on the host (per-interface bytes/packets and rates over a short
// sampling window) and returns it as the result payload. The traffic sampler is
// injectable so tests don't touch /proc or wait.
async function runTest(command = {}, { sampler = sampleTraffic } = {}) {
  const name = (command && (command.name || command.test)) || 'traffic';
  const intervalMs = command && Number.isInteger(command.intervalMs) ? command.intervalMs : 1000;
  const startedAt = new Date().toISOString();

  const traffic = await sampler({ intervalMs });

  return {
    name,
    commandId: (command && command.id) ?? null,
    ok: true,
    startedAt,
    finishedAt: new Date().toISOString(),
    traffic,
  };
}

module.exports = { runTest };
