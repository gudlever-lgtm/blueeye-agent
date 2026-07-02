'use strict';

const { execFile } = require('child_process');

// Parses `netstat -ib` output into per-interface cumulative counters.
// Only Link-type lines (containing <Link#N>) are processed — IPv4/IPv6 rows
// repeat the same counters and must be skipped to avoid double-counting.
// Column order: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll [Drop]
function parseNetstatIb(text) {
  const result = {};
  for (const line of String(text).split('\n')) {
    if (!line.includes('<Link#')) continue;
    const cols = line.trim().split(/\s+/);
    if (cols.length < 10) continue;
    const iface = cols[0];
    result[iface] = {
      rxPackets: Number(cols[4]) || 0,
      rxErrors:  Number(cols[5]) || 0,
      rxBytes:   Number(cols[6]) || 0,
      txPackets: Number(cols[7]) || 0,
      txErrors:  Number(cols[8]) || 0,
      txBytes:   Number(cols[9]) || 0,
    };
  }
  return result;
}

function runNetstat() {
  return new Promise((resolve) => {
    execFile('netstat', ['-ib'], { timeout: 5000 }, (err, stdout) => {
      if (err) { resolve({}); return; }
      try { resolve(parseNetstatIb(stdout)); } catch { resolve({}); }
    });
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const MAX_INTERFACES = 64;

// Same contract as trafficMonitor.sampleTraffic — reads cumulative counters
// twice, computes per-interface deltas and rates, returns the same snapshot
// shape. operStatus/speedMbps are always null on macOS (no sysfs equivalent).
async function sampleTraffic({
  runNetstatFn = runNetstat,
  intervalMs = 1000,
  sleepFn = sleep,
  now = () => Date.now(),
  includeLoopback = false,
  maxInterfaces = MAX_INTERFACES,
} = {}) {
  const t0 = now();
  const first = await runNetstatFn();
  await sleepFn(intervalMs);
  const t1 = now();
  const second = await runNetstatFn();

  const elapsedSec = Math.max((t1 - t0) / 1000, 0.001);
  const entries = [];
  const totals = { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0, rxErrors: 0, txErrors: 0, rxDrop: 0, txDrop: 0 };
  const delta = (a, b, k) => Math.max((a[k] || 0) - (b[k] || 0), 0);

  for (const iface of Object.keys(second)) {
    if (!includeLoopback && iface === 'lo0') continue;
    if (!first[iface]) continue;
    const rxBytes   = delta(second[iface], first[iface], 'rxBytes');
    const txBytes   = delta(second[iface], first[iface], 'txBytes');
    const rxPackets = delta(second[iface], first[iface], 'rxPackets');
    const txPackets = delta(second[iface], first[iface], 'txPackets');
    const rxErrors  = delta(second[iface], first[iface], 'rxErrors');
    const txErrors  = delta(second[iface], first[iface], 'txErrors');
    totals.rxBytes += rxBytes; totals.txBytes += txBytes;
    totals.rxPackets += rxPackets; totals.txPackets += txPackets;
    totals.rxErrors += rxErrors; totals.txErrors += txErrors;
    entries.push({
      iface,
      rxBytes, txBytes, rxPackets, txPackets,
      rxBytesPerSec: Math.round(rxBytes / elapsedSec),
      txBytesPerSec: Math.round(txBytes / elapsedSec),
      rxErrors, txErrors,
      rxDrop: 0, txDrop: 0,
    });
  }

  let interfacesOmitted = 0;
  if (entries.length > maxInterfaces) {
    entries.sort((a, b) => (b.rxBytes + b.txBytes) - (a.rxBytes + a.txBytes));
    interfacesOmitted = entries.length - maxInterfaces;
    entries.length = maxInterfaces;
  }

  const interfaces = entries.map((e) => ({ ...e, operStatus: null, speedMbps: null }));

  return {
    intervalMs,
    elapsedSec: Math.round(elapsedSec * 1000) / 1000,
    interfaces,
    ...(interfacesOmitted ? { interfacesOmitted } : {}),
    totals: {
      ...totals,
      rxBytesPerSec: Math.round(totals.rxBytes / elapsedSec),
      txBytesPerSec: Math.round(totals.txBytes / elapsedSec),
    },
  };
}

module.exports = { parseNetstatIb, sampleTraffic, MAX_INTERFACES };
