'use strict';

const { sampleTraffic } = require('./trafficMonitor');
const { sampleSystem } = require('./systemMetrics');

// Runs a "test" in response to a server command. It measures, over a short
// window, both real network traffic (per-interface bytes/rates, or flow
// summaries from a netflow/sflow source) and host performance metrics
// (CPU/memory/load/uptime), returning them as the result payload. Both samplers
// are injectable so tests don't touch /proc or wait.
async function runTest(command = {}, { sampler = sampleTraffic, systemSampler = sampleSystem } = {}) {
  const name = (command && (command.name || command.test)) || 'traffic';
  const intervalMs = command && Number.isInteger(command.intervalMs) ? command.intervalMs : 1000;
  const startedAt = new Date().toISOString();

  // Sample traffic and system metrics over the same window, in parallel. System
  // metrics are best-effort: a failure there must not lose the traffic report.
  const [traffic, system] = await Promise.all([
    sampler({ intervalMs }),
    Promise.resolve().then(() => systemSampler({ intervalMs })).catch(() => null),
  ]);

  return {
    name,
    commandId: (command && command.id) ?? null,
    ok: true,
    startedAt,
    finishedAt: new Date().toISOString(),
    traffic,
    system,
  };
}

module.exports = { runTest };
