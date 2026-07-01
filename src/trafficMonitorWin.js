'use strict';

const { spawn } = require('child_process');
const readline = require('readline');
const { buildSnapshot } = require('./trafficMonitor');
const { computeBackoff } = require('./backoff');
const { silentLogger } = require('./logger');

// Windows traffic source: there is no /proc/net/dev, so a persistent
// powershell.exe process is spawned ONCE (not per poll) and ticks on its own
// timer, emitting one JSON line per tick with cumulative per-adapter counters
// in exactly the field shape parseProcNetDev returns (rxBytes/rxPackets/
// rxErrors/rxDrop/txBytes/txPackets/txErrors/txDrop), so buildSnapshot() from
// trafficMonitor.js can be reused unchanged for the delta/rate computation.
//
// Get-NetAdapterStatistics exposes exactly those eight cumulative counters
// (Received/Sent Bytes, Unicast+Multicast+Broadcast packets, PacketErrors,
// DiscardedPackets), and Get-NetAdapter supplies best-effort link state
// (Status) + speed (LinkSpeed) for the operStatus/speedMbps meta fields.
//
// Inline script (no separate .ps1 file) so a server self-update that ships a
// new trafficMonitorWin.js carries the tick logic with it automatically.
const TICK_MS = 1000;

function buildScript(tickMs) {
  return (
    "$ErrorActionPreference = 'SilentlyContinue'; " +
    'while ($true) { ' +
    '$ifaces = @{}; ' +
    '$adapters = @{}; ' +
    'foreach ($a in Get-NetAdapter) { $adapters[$a.Name] = $a } ' +
    'foreach ($s in Get-NetAdapterStatistics) { ' +
    '$a = $adapters[$s.Name]; ' +
    '$speed = $null; ' +
    'if ($a -and $a.LinkSpeed) { try { $speed = [math]::Round([double]$a.LinkSpeed / 1000000) } catch {} } ' +
    '$ifaces[$s.Name] = @{ ' +
    'rxBytes = [int64]$s.ReceivedBytes; ' +
    'rxPackets = [int64]($s.ReceivedUnicastPackets + $s.ReceivedMulticastPackets + $s.ReceivedBroadcastPackets); ' +
    'rxErrors = [int64]$s.ReceivedPacketErrors; ' +
    'rxDrop = [int64]$s.ReceivedDiscardedPackets; ' +
    'txBytes = [int64]$s.SentBytes; ' +
    'txPackets = [int64]($s.SentUnicastPackets + $s.SentMulticastPackets + $s.SentBroadcastPackets); ' +
    'txErrors = [int64]$s.OutboundPacketErrors; ' +
    'txDrop = [int64]$s.OutboundDiscardedPackets; ' +
    'operStatus = if ($a) { $a.Status.ToString() } else { $null }; ' +
    'speedMbps = $speed ' +
    '} } ' +
    '$line = @{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); ifaces = $ifaces } | ConvertTo-Json -Compress -Depth 6; ' +
    'Write-Output $line; ' +
    `Start-Sleep -Milliseconds ${tickMs}; ` +
    '}'
  );
}

// Bound on buffered ticks (keeps memory flat even if a caller never asks for a
// sample for a long time).
const MAX_READINGS = 120;
// Slack allowed on top of the requested intervalMs (and, at startup, on top
// of tickMs) before giving up and returning an empty-but-valid snapshot
// instead of hanging the report loop forever (e.g. powershell.exe crash-loop).
const READING_GRACE_MS = 5000;
const POLL_STEP_MS = 50;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function parseLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null; // half-written / corrupt line from a mid-write pipe read: skip
  }
  if (!parsed || typeof parsed !== 'object') return null;
  if (typeof parsed.ts !== 'number' || !Number.isFinite(parsed.ts)) return null;
  if (!parsed.ifaces || typeof parsed.ifaces !== 'object') return null;
  return { ts: parsed.ts, ifaces: parsed.ifaces };
}

// Creates a win32 traffic sampler: async ({ intervalMs }) => snapshot, matching
// trafficMonitor.js's sampleTraffic contract, plus a .stop() (like the
// netflow/sflow collector samplers) to tear down the background process.
// spawnFn/now/waitMs are injectable for tests so no real powershell.exe runs.
function createWinTrafficSampler({
  spawnFn = spawn,
  tickMs = TICK_MS,
  logger = silentLogger,
  includeLoopback = false,
  maxInterfaces,
  now = () => Date.now(),
  waitMs = sleep,
  graceMs = READING_GRACE_MS,
  respawnBaseMs = 1000,
  respawnMaxMs = 30000,
} = {}) {
  let child = null;
  let rl = null;
  let stopped = false;
  let attempt = 0;
  let respawnTimer = null;
  const readings = []; // { ts, ifaces }, oldest first

  function pushReading(reading) {
    readings.push(reading);
    if (readings.length > MAX_READINGS) readings.shift();
  }

  function handleLine(line) {
    const reading = parseLine(line);
    if (reading) pushReading(reading);
  }

  function scheduleRespawn() {
    if (stopped) return;
    attempt += 1;
    const delay = computeBackoff(attempt, { baseMs: respawnBaseMs, maxMs: respawnMaxMs });
    logger.warn(`Windows traffic source: powershell.exe exited; respawning in ${delay}ms`);
    respawnTimer = setTimeout(spawnProcess, delay);
  }

  function spawnProcess() {
    if (stopped) return;
    respawnTimer = null;
    let proc;
    try {
      proc = spawnFn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', buildScript(tickMs)], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      logger.warn(`Windows traffic source: failed to spawn powershell.exe (${err.message})`);
      scheduleRespawn();
      return;
    }
    child = proc;
    rl = readline.createInterface({ input: proc.stdout });
    rl.on('line', handleLine);
    if (proc.stderr) proc.stderr.on('data', () => {}); // best-effort; never crash on stderr noise
    proc.on('error', (err) => logger.warn(`Windows traffic source: powershell.exe error (${err.message})`));
    proc.on('exit', () => {
      if (rl) { rl.close(); rl = null; }
      child = null;
      scheduleRespawn();
    });
    proc.once('spawn', () => { attempt = 0; });
  }

  spawnProcess();

  function emptySnapshot(intervalMs) {
    return {
      intervalMs,
      elapsedSec: 0.001,
      interfaces: [],
      totals: {
        rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0,
        rxBytesPerSec: 0, txBytesPerSec: 0,
      },
    };
  }

  // Waits (until `deadline`, a now()-scale timestamp) for the newest buffered
  // reading once it satisfies `isReady`, polling every POLL_STEP_MS.
  async function waitUntil(deadline, isReady) {
    for (;;) {
      const last = readings[readings.length - 1];
      if (last && isReady(last)) return last;
      if (now() >= deadline) return last || null;
      await waitMs(POLL_STEP_MS);
    }
  }

  // Mirrors sampleTraffic's "read now, sleep intervalMs, read again" window:
  // `first` is whatever's freshest right now, `second` is the first reading
  // at or after first.ts + intervalMs — so elapsedSec tracks the requested
  // interval instead of the (possibly different) PowerShell tick cadence.
  async function sample({ intervalMs = 1000 } = {}) {
    const first = await waitUntil(now() + tickMs + graceMs, () => true);
    if (!first) return emptySnapshot(intervalMs); // powershell.exe hasn't produced a tick yet

    const second = await waitUntil(now() + intervalMs + graceMs, (r) => r.ts >= first.ts + intervalMs);
    if (!second || second.ts <= first.ts) return emptySnapshot(intervalMs);

    const meta = {};
    for (const [iface, v] of Object.entries(second.ifaces)) {
      meta[iface] = { operStatus: (v && v.operStatus) ?? null, speedMbps: (v && v.speedMbps) ?? null };
    }
    const elapsedSec = Math.max((second.ts - first.ts) / 1000, 0.001);
    return buildSnapshot(first.ifaces, second.ifaces, {
      intervalMs,
      elapsedSec,
      includeLoopback,
      maxInterfaces,
      readIfaceMeta: async (iface) => meta[iface] || { operStatus: null, speedMbps: null },
    });
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    if (respawnTimer) { clearTimeout(respawnTimer); respawnTimer = null; }
    if (rl) { rl.close(); rl = null; }
    if (child) {
      try { child.kill(); } catch { /* already gone */ }
      child = null;
    }
  }

  // Test-only escape hatch: feed a raw stdout line as if powershell.exe wrote
  // it, bypassing the real process/readline plumbing (mirrors the netflow/
  // sflow collectors' `_feed`).
  sample._feed = handleLine;
  sample.stop = stop;
  return sample;
}

module.exports = { createWinTrafficSampler, buildScript, parseLine };
