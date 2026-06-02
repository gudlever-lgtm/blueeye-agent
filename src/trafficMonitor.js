'use strict';

const fs = require('fs');

// Parses the contents of /proc/net/dev into per-interface counters.
// Column layout after "iface:": rx = bytes packets errs drop fifo frame
// compressed multicast (0-7), tx = bytes packets errs drop fifo colls carrier
// compressed (8-15). So rxBytes=col[0], rxErrors=col[2], txBytes=col[8], etc.
function parseProcNetDev(text) {
  const result = {};
  for (const line of String(text).split('\n')) {
    const match = line.match(/^\s*([^:]+):\s*(.*)$/);
    if (!match) continue;
    const iface = match[1].trim();
    const cols = match[2].trim().split(/\s+/).map(Number);
    if (cols.length < 16) continue;
    result[iface] = {
      rxBytes: cols[0],
      rxPackets: cols[1],
      rxErrors: cols[2],
      rxDrop: cols[3],
      txBytes: cols[8],
      txPackets: cols[9],
      txErrors: cols[10],
      txDrop: cols[11],
    };
  }
  return result;
}

function defaultReadProc() {
  return fs.readFileSync('/proc/net/dev', 'utf8');
}

// Best-effort link state + speed for an interface, from sysfs. Returns nulls if
// unavailable (virtual/down interfaces, non-Linux). Async so it never blocks the
// event loop during continuous reporting. Injectable for tests.
async function defaultReadIfaceMeta(iface) {
  let operStatus = null;
  let speedMbps = null;
  try { operStatus = (await fs.promises.readFile(`/sys/class/net/${iface}/operstate`, 'utf8')).trim() || null; } catch { /* n/a */ }
  try {
    const s = Number((await fs.promises.readFile(`/sys/class/net/${iface}/speed`, 'utf8')).trim());
    if (Number.isFinite(s) && s > 0) speedMbps = s;
  } catch { /* speed unreadable for many ifaces */ }
  return { operStatus, speedMbps };
}

function snapshot(readProc) {
  try {
    return parseProcNetDev(readProc());
  } catch {
    return {};
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Samples network traffic by reading /proc/net/dev twice `intervalMs` apart and
// computing per-interface deltas and rates. Counters are injectable for tests.
async function sampleTraffic({
  readProc = defaultReadProc,
  intervalMs = 1000,
  sleepFn = sleep,
  now = () => Date.now(),
  includeLoopback = false,
  readIfaceMeta = defaultReadIfaceMeta,
} = {}) {
  const t0 = now();
  const first = snapshot(readProc);
  await sleepFn(intervalMs);
  const t1 = now();
  const second = snapshot(readProc);

  const elapsedSec = Math.max((t1 - t0) / 1000, 0.001);
  const interfaces = [];
  const totals = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 };
  const delta = (a, b, k) => Math.max((a[k] || 0) - (b[k] || 0), 0);

  for (const iface of Object.keys(second)) {
    if (!includeLoopback && iface === 'lo') continue;
    if (!first[iface]) continue;
    const rxBytes = delta(second[iface], first[iface], 'rxBytes');
    const txBytes = delta(second[iface], first[iface], 'txBytes');
    const rxPackets = delta(second[iface], first[iface], 'rxPackets');
    const txPackets = delta(second[iface], first[iface], 'txPackets');
    const rxErrors = delta(second[iface], first[iface], 'rxErrors');
    const txErrors = delta(second[iface], first[iface], 'txErrors');
    const rxDrop = delta(second[iface], first[iface], 'rxDrop');
    const txDrop = delta(second[iface], first[iface], 'txDrop');
    totals.rxBytes += rxBytes; totals.txBytes += txBytes;
    totals.rxPackets += rxPackets; totals.txPackets += txPackets;
    totals.rxErrors += rxErrors; totals.txErrors += txErrors;
    totals.rxDrop += rxDrop; totals.txDrop += txDrop;
    const meta = await readIfaceMeta(iface);
    interfaces.push({
      iface,
      rxBytes,
      txBytes,
      rxPackets,
      txPackets,
      rxBytesPerSec: Math.round(rxBytes / elapsedSec),
      txBytesPerSec: Math.round(txBytes / elapsedSec),
      rxErrors,
      txErrors,
      rxDrop,
      txDrop,
      operStatus: meta.operStatus,
      speedMbps: meta.speedMbps,
    });
  }

  return {
    intervalMs,
    elapsedSec: Math.round(elapsedSec * 1000) / 1000,
    interfaces,
    totals: {
      ...totals,
      rxBytesPerSec: Math.round(totals.rxBytes / elapsedSec),
      txBytesPerSec: Math.round(totals.txBytes / elapsedSec),
    },
  };
}

module.exports = { parseProcNetDev, snapshot, sampleTraffic, defaultReadIfaceMeta };
