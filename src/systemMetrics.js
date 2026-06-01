'use strict';

const os = require('os');

// Samples host performance metrics (CPU utilisation, memory, load, uptime) using
// Node's built-in os module — no external dependencies. CPU utilisation is the
// busy fraction across all cores between two cpu-tick snapshots taken intervalMs
// apart. os.cpus() is injectable for tests.
function cpuTotals(cpus) {
  let idle = 0;
  let total = 0;
  for (const c of cpus) {
    for (const t of Object.values(c.times)) total += t;
    idle += c.times.idle;
  }
  return { idle, total };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function sampleSystem({
  intervalMs = 1000,
  cpus = () => os.cpus(),
  totalmem = () => os.totalmem(),
  freemem = () => os.freemem(),
  loadavg = () => os.loadavg(),
  uptime = () => os.uptime(),
  sleepFn = sleep,
} = {}) {
  const a = cpuTotals(cpus());
  await sleepFn(intervalMs);
  const b = cpuTotals(cpus());

  const totalDelta = b.total - a.total;
  const idleDelta = b.idle - a.idle;
  // Busy fraction; guard against a zero/again-identical snapshot.
  const cpuPercent = totalDelta > 0 ? Math.max(0, Math.min(100, (1 - idleDelta / totalDelta) * 100)) : 0;

  const total = totalmem();
  const free = freemem();
  const used = Math.max(0, total - free);

  return {
    cpuPercent: Math.round(cpuPercent * 10) / 10,
    cpuCount: cpus().length,
    loadavg: loadavg(),
    memTotalBytes: total,
    memUsedBytes: used,
    memFreeBytes: free,
    memUsedPercent: total > 0 ? Math.round((used / total) * 1000) / 10 : 0,
    uptimeSec: Math.round(uptime()),
  };
}

module.exports = { sampleSystem, cpuTotals };
