'use strict';

const { defaultRouteInterface } = require('../probes/targets');

// Renders an /etc/hsflowd.conf for the Host sFlow daemon (hsflowd) that turns a
// plain Linux host into an sFlow v5 EXPORTER: it samples the host's own packets
// and reads interface counters, then ships them to a collector. We point it at
// the agent's local collector (127.0.0.1:6343 by default), so a host with no
// switch doing sFlow export still produces the src/dst flow data the server's
// Destinations map is built from.
//
// Format follows hsflowd's modular config (v2.x):
//   sflow {
//     collector { ip = 127.0.0.1  udpport = 6343 }
//     sampling = 256
//     polling  = 20
//     pcap { dev = eth0 }
//   }
// `pcap { dev }` is what makes hsflowd sample PACKETS (the 5-tuple data); without
// an interface it would export interface counters only. The device name varies
// per host (eth0/ens.../wlan0), so it is configurable and defaults to eth0.

const DEFAULTS = {
  collectorIp: '127.0.0.1',
  collectorPort: 6343,
  samplingRate: 256,
  pollingSecs: 20,
  device: 'eth0',
};

// First line of every conf this agent writes — and the marker by which the
// agent (and uninstall.sh) recognises an hsflowd installation IT manages, so a
// delete / source change stops our exporter without ever touching an
// operator-managed hsflowd. Must stay a prefix of the rendered first line.
const MANAGED_MARKER = '# Managed by blueeye-agent';

// hsflowd config values are written verbatim into the file, so constrain them to
// safe shapes (no newlines / braces) — never interpolate untrusted free text.
const SAFE_DEVICE = /^[A-Za-z0-9._:-]{1,32}$/;
const SAFE_IP = /^[0-9a-fA-F.:]{1,45}$/;

function posInt(v, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  return Number.isInteger(v) && v >= min && v <= max ? v : fallback;
}

// Returns the effective, sanitised options actually used (handy for logging and
// for the manager to compare against an existing file).
function hsflowdOptions(opts = {}) {
  const o = opts && typeof opts === 'object' ? opts : {};
  return {
    collectorIp: typeof o.collectorIp === 'string' && SAFE_IP.test(o.collectorIp) ? o.collectorIp : DEFAULTS.collectorIp,
    collectorPort: posInt(o.collectorPort, DEFAULTS.collectorPort, { max: 65535 }),
    samplingRate: posInt(o.samplingRate, DEFAULTS.samplingRate, { max: 16777216 }),
    pollingSecs: posInt(o.pollingSecs, DEFAULTS.pollingSecs, { max: 86400 }),
    device: typeof o.device === 'string' && SAFE_DEVICE.test(o.device) ? o.device : DEFAULTS.device,
  };
}

function renderHsflowdConf(opts = {}) {
  const o = hsflowdOptions(opts);
  return [
    `${MANAGED_MARKER} — do not edit by hand; changes are overwritten.`,
    '# Host sFlow exporter: samples this host and exports to the local BlueEye collector.',
    'sflow {',
    `  collector { ip = ${o.collectorIp}  udpport = ${o.collectorPort} }`,
    `  sampling = ${o.samplingRate}`,
    `  polling = ${o.pollingSecs}`,
    `  pcap { dev = ${o.device} }`,
    '}',
    '',
  ].join('\n');
}

// Chooses which interface hsflowd should sample. An explicitly-configured device
// that EXISTS on the host wins; otherwise (blank, or a stale name like the default
// 'eth0' on a cloud instance that actually uses ens3) fall back to the default-
// route interface, then the first non-loopback interface. Returns null when we
// cannot enumerate interfaces, so the caller keeps whatever was configured.
function pickSamplingDevice({ configured = null, interfaces = [], routeText = '' } = {}) {
  const names = (Array.isArray(interfaces) ? interfaces : []).filter((n) => n && n !== 'lo');
  if (!names.length) return configured || null; // can't verify — trust the config
  if (configured && names.includes(configured)) return configured; // explicit + present
  const viaRoute = defaultRouteInterface(routeText);
  if (viaRoute && names.includes(viaRoute)) return viaRoute; // default-route NIC
  return names[0]; // first real (non-loopback) NIC
}

module.exports = { renderHsflowdConf, hsflowdOptions, pickSamplingDevice, DEFAULTS, MANAGED_MARKER };
