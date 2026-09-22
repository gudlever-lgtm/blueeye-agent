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
    // Column layout: Name Mtu Network [Address] Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
    // The Address column (MAC) is present only for Ethernet-style interfaces; loopback
    // omits it, shifting everything one position left. Detect by checking whether col[3]
    // looks like a MAC (contains ':') or is already a number (Ipkts without MAC).
    const hasMac = cols[3] && cols[3].includes(':');
    const base = hasMac ? 4 : 3; // index of Ipkts
    if (cols.length < base + 6) continue;
    const iface = cols[0];
    result[iface] = {
      rxPackets: Number(cols[base])     || 0,
      rxErrors:  Number(cols[base + 1]) || 0,
      rxBytes:   Number(cols[base + 2]) || 0,
      txPackets: Number(cols[base + 3]) || 0,
      txErrors:  Number(cols[base + 4]) || 0,
      txBytes:   Number(cols[base + 5]) || 0,
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

// Link state + wired speed from `ifconfig` (all interfaces, one call).
//   flags=8863<UP,BROADCAST,SMART,RUNNING,...>  -> admin state
//   status: active | inactive                   -> carrier (NICs only)
//   media: autoselect (1000baseT <full-duplex>) -> negotiated rate
// Interfaces with no status line (lo0, utun*, gif0) report 'up' while RUNNING,
// like Linux reports 'unknown' for a tun device. A bridge's `member:` ports
// (the Thunderbolt Bridge's en1/en2… on almost every Mac) are left null: an
// unused Thunderbolt port is not a link fault, and the bridge itself carries
// the state.
function parseIfconfig(text) {
  const result = {};
  const members = new Set();
  let cur = null;
  for (const line of String(text).split('\n')) {
    const head = /^([A-Za-z0-9_.-]+): flags=[0-9a-fA-F]+<([^>]*)>/.exec(line);
    if (head) {
      const flags = head[2].split(',');
      cur = { up: flags.includes('UP'), running: flags.includes('RUNNING'), status: null, speedMbps: null };
      result[head[1]] = cur;
      continue;
    }
    if (!cur) continue;
    const t = line.trim();
    let m;
    if ((m = /^status: (\w+)/.exec(t))) cur.status = m[1].toLowerCase();
    else if ((m = /^media: .*\((\d+(?:\.\d+)?)(G?)base/i.exec(t))) {
      const n = Number(m[1]) * (m[2] ? 1000 : 1);
      if (n > 0) cur.speedMbps = n;
    } else if ((m = /^member: (\S+)/.exec(t))) members.add(m[1]);
  }
  const meta = {};
  for (const [iface, v] of Object.entries(result)) {
    let operStatus;
    if (members.has(iface)) operStatus = null;
    else if (!v.up) operStatus = 'down';
    else if (v.status === 'active') operStatus = 'up';
    else if (v.status === 'inactive') operStatus = 'down';
    else operStatus = v.running ? 'up' : 'unknown';
    meta[iface] = { operStatus, speedMbps: operStatus === 'up' ? v.speedMbps : null };
  }
  return meta;
}

// Wi-Fi reports `media: autoselect` with no rate; the current transmit rate
// (Mbit/s) is in system_profiler's AirPort data, keyed by BSD name (en0).
function parseAirportJson(text) {
  const out = {};
  let data;
  try { data = JSON.parse(text); } catch { return out; }
  const top = data && Array.isArray(data.SPAirPortDataType) ? data.SPAirPortDataType : [];
  for (const entry of top) {
    for (const i of (entry && Array.isArray(entry.spairport_airport_interfaces) ? entry.spairport_airport_interfaces : [])) {
      const rate = Number(i && i.spairport_current_network_information && i.spairport_current_network_information.spairport_network_rate);
      if (i && typeof i._name === 'string' && Number.isFinite(rate) && rate > 0) out[i._name] = rate;
    }
  }
  return out;
}

function runCmd(cmd, args, timeout) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => resolve(err ? '' : stdout));
  });
}

// system_profiler takes a second or more, so its answer is cached and refreshed
// in the background; a sample never waits on it.
const WIFI_TTL_MS = 60 * 1000;

function createMetaReader({ run = runCmd, now = () => Date.now(), wifiTtlMs = WIFI_TTL_MS } = {}) {
  let wifi = {};
  let wifiAt = -Infinity;
  let wifiPending = null;

  function refreshWifi() {
    if (wifiPending || now() - wifiAt < wifiTtlMs) return wifiPending;
    wifiPending = run('system_profiler', ['SPAirPortDataType', '-json'], 15000)
      .then((out) => { wifi = parseAirportJson(out); })
      .catch(() => {})
      .finally(() => { wifiAt = now(); wifiPending = null; });
    return wifiPending;
  }

  return async function readMeta() {
    refreshWifi();
    let meta = {};
    try { meta = parseIfconfig(await run('ifconfig', [], 5000)); } catch { /* no meta */ }
    for (const [iface, rate] of Object.entries(wifi)) {
      if (meta[iface] && meta[iface].operStatus === 'up' && !meta[iface].speedMbps) meta[iface].speedMbps = rate;
    }
    return meta;
  };
}

const defaultReadMeta = createMetaReader();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const MAX_INTERFACES = 64;

// Same contract as trafficMonitor.sampleTraffic — reads cumulative counters
// twice, computes per-interface deltas and rates, returns the same snapshot
// shape. operStatus/speedMbps come from ifconfig (+ system_profiler for Wi-Fi).
async function sampleTraffic({
  runNetstatFn = runNetstat,
  readMetaFn = defaultReadMeta,
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

  let meta = {};
  try { meta = (await readMetaFn()) || {}; } catch { /* link state is best-effort */ }
  const interfaces = entries.map((e) => ({
    ...e,
    operStatus: (meta[e.iface] && meta[e.iface].operStatus) || null,
    speedMbps: (meta[e.iface] && meta[e.iface].speedMbps) || null,
  }));

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

module.exports = { parseNetstatIb, parseIfconfig, parseAirportJson, createMetaReader, sampleTraffic, MAX_INTERFACES };
