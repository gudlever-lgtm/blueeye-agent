'use strict';

const { execFile } = require('child_process');
const fs = require('fs');

// Collects per-NIC driver + firmware identity from the host so the server can
// spot firmware drift across a fleet (e.g. 3 of 50 units on a different Wi-Fi
// firmware). Linux-only and best-effort: every source is optional and any
// failure degrades to null/[] rather than throwing.
//
// The authoritative source of a NIC's firmware version is `ethtool -i <iface>`
// (driver / version / firmware-version / bus-info). `ethtool -i` only queries
// the driver — it does not touch the device — so it works for an unprivileged
// user; sysfs fills in a stable hardware id without any binary.
//
// Privacy: metadata only — driver/firmware strings + the PCI/USB vendor:device
// id. No MAC address, no payload.

const ETHTOOL_TIMEOUT_MS = 4000;
const MAX_FIELD = 256;

// ethtool prints these placeholders for drivers that have no real value (e.g.
// software bridges/veth report `firmware-version: N/A`). Treat them as absent so
// a bridge with no bus/PCI id and no real firmware is dropped, not listed as a
// "NIC" with firmware "N/A".
const PLACEHOLDERS = new Set(['', 'n/a', 'na', 'none', 'unknown']);
function cleanField(value) {
  if (value == null) return null;
  const t = String(value).trim();
  return PLACEHOLDERS.has(t.toLowerCase()) ? null : t;
}

// Parses `ethtool -i <iface>` output (key: value lines) into the fields we keep.
function parseEthtoolInfo(text) {
  const out = { driver: null, driverVersion: null, firmwareVersion: null, busInfo: null };
  for (const line of String(text).split('\n')) {
    const m = line.match(/^([^:]+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1].trim().toLowerCase();
    const value = m[2].trim();
    if (key === 'driver') out.driver = value || null;
    else if (key === 'version') out.driverVersion = cleanField(value);
    else if (key === 'firmware-version') out.firmwareVersion = cleanField(value);
    else if (key === 'bus-info') out.busInfo = cleanField(value);
  }
  return out;
}

// Default interface lister: every real, non-loopback interface from sysfs.
async function defaultListIfaces() {
  try {
    const entries = await fs.promises.readdir('/sys/class/net');
    return entries.filter((i) => i && i !== 'lo');
  } catch {
    return [];
  }
}

// Default ethtool runner: resolves the `ethtool -i <iface>` stdout, or null if
// ethtool is missing / errors / times out (never throws).
function defaultRunEthtool(iface) {
  return new Promise((resolve) => {
    execFile('ethtool', ['-i', iface], { timeout: ETHTOOL_TIMEOUT_MS }, (err, stdout) => {
      if (err) return resolve(null);
      resolve(String(stdout || ''));
    });
  });
}

// Best-effort PCI/USB vendor:device id for an interface, from sysfs.
async function defaultReadSysfsId(iface) {
  const read = async (p) => {
    try { return (await fs.promises.readFile(p, 'utf8')).trim() || null; } catch { return null; }
  };
  const vendor = await read(`/sys/class/net/${iface}/device/vendor`);
  const device = await read(`/sys/class/net/${iface}/device/device`);
  if (vendor && device) return `${vendor.replace(/^0x/, '')}:${device.replace(/^0x/, '')}`;
  return null;
}

const clip = (s) => (s == null ? null : String(s).slice(0, MAX_FIELD));

// Collects NIC info for every physical interface. Returns an array of
// { iface, driver, driverVersion, firmwareVersion, busInfo, pciId }. Virtual
// interfaces (no bus-info, no firmware, no PCI id) are dropped — they are noise
// for firmware-drift comparison. Non-Linux / no-ethtool hosts return [].
async function collectNicInfo({
  platform = process.platform,
  listIfaces = defaultListIfaces,
  runEthtool = defaultRunEthtool,
  readSysfsId = defaultReadSysfsId,
} = {}) {
  if (platform !== 'linux') return [];
  let ifaces;
  try { ifaces = await listIfaces(); } catch { return []; }
  if (!Array.isArray(ifaces) || !ifaces.length) return [];

  const nics = [];
  for (const iface of ifaces) {
    let info = { driver: null, driverVersion: null, firmwareVersion: null, busInfo: null };
    try {
      const text = await runEthtool(iface);
      if (text) info = parseEthtoolInfo(text);
    } catch { /* best-effort per iface */ }
    const pciId = await readSysfsId(iface).catch(() => null);
    // Keep only real NICs: something with a bus address, a firmware string or a
    // PCI/USB id. Pure-virtual interfaces (bridge/veth/tun) have none and are
    // skipped so they don't pollute the firmware comparison.
    if (!info.busInfo && !info.firmwareVersion && !pciId) continue;
    nics.push({
      iface: clip(iface),
      driver: clip(info.driver),
      driverVersion: clip(info.driverVersion),
      firmwareVersion: clip(info.firmwareVersion),
      busInfo: clip(info.busInfo),
      pciId: clip(pciId),
    });
  }
  return nics;
}

module.exports = { collectNicInfo, parseEthtoolInfo };
