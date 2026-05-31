'use strict';

const fs = require('fs');

// Parses the contents of /proc/net/dev into
//   { <iface>: { rxBytes, rxPackets, txBytes, txPackets } }.
// Column layout after "iface:": rx = bytes packets errs drop fifo frame
// compressed multicast (8), tx = bytes packets errs drop fifo colls carrier
// compressed (8). So rxBytes = col[0], txBytes = col[8].
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
      txBytes: cols[8],
      txPackets: cols[9],
    };
  }
  return result;
}

function defaultReadProc() {
  return fs.readFileSync('/proc/net/dev', 'utf8');
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
} = {}) {
  const t0 = now();
  const first = snapshot(readProc);
  await sleepFn(intervalMs);
  const t1 = now();
  const second = snapshot(readProc);

  const elapsedSec = Math.max((t1 - t0) / 1000, 0.001);
  const interfaces = [];
  const totals = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 };

  for (const iface of Object.keys(second)) {
    if (!includeLoopback && iface === 'lo') continue;
    if (!first[iface]) continue;
    const rxBytes = Math.max(second[iface].rxBytes - first[iface].rxBytes, 0);
    const txBytes = Math.max(second[iface].txBytes - first[iface].txBytes, 0);
    const rxPackets = Math.max(second[iface].rxPackets - first[iface].rxPackets, 0);
    const txPackets = Math.max(second[iface].txPackets - first[iface].txPackets, 0);
    totals.rxBytes += rxBytes;
    totals.txBytes += txBytes;
    totals.rxPackets += rxPackets;
    totals.txPackets += txPackets;
    interfaces.push({
      iface,
      rxBytes,
      txBytes,
      rxPackets,
      txPackets,
      rxBytesPerSec: Math.round(rxBytes / elapsedSec),
      txBytesPerSec: Math.round(txBytes / elapsedSec),
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

module.exports = { parseProcNetDev, snapshot, sampleTraffic };
