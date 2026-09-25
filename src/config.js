'use strict';

const fs = require('fs');
const path = require('path');
const { parseConfiguredTargets } = require('./probes/targets');
const { normalizeFingerprint, normalizeFingerprints } = require('./fingerprint');

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

// Truthy unless explicitly turned off ("0"/"false"/"no"/"off"). env wins over
// the JSON file; falls back to `dflt` when neither is set.
function toBool(envVal, fileVal, dflt) {
  const v = envVal !== undefined ? envVal : fileVal;
  if (v === undefined || v === null || v === '') return dflt;
  if (typeof v === 'boolean') return v;
  return !['0', 'false', 'no', 'off'].includes(String(v).toLowerCase());
}

// A list setting: an array (JSON file) or one comma/space-separated string
// (env var). Always returns an array of non-empty trimmed strings.
function toList(v) {
  if (Array.isArray(v)) return v.map((x) => String(x == null ? '' : x).trim()).filter(Boolean);
  if (typeof v === 'string') return v.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
  return [];
}

// Default the config file to the agent's OWN directory (next to package.json),
// not process.cwd(): the enroll one-shot runs `node <dir>/src/index.js` without
// cd-ing into the install dir, so cwd must not decide where config lives — and if
// cwd was deleted out from under the process (e.g. uninstall.sh removed it), even
// reading process.cwd() throws (uv_cwd ENOENT) and startup dies before loading a
// single setting. Mirrors how tokenPath is resolved below.
//
// NB: under the versioned-release layout (`current` -> releases/<v> symlink),
// __dirname resolves INTO the swappable release dir, so the systemd installer pins
// BLUEEYE_AGENT_CONFIG to a stable state path (/var/lib/blueeye-agent) — otherwise
// config persisted post-enroll (serverUrl / discovered cert fingerprint) would be
// abandoned on the next atomic swap. The __dirname default is for the flat enroll
// layout (/opt/blueeye-agent, no symlink), where it IS the stable dir.
function configPathFrom(env) {
  return env.BLUEEYE_AGENT_CONFIG || path.join(__dirname, '..', 'blueeye-agent.config.json');
}

function readConfigFile(configPath) {
  if (!fs.existsSync(configPath)) return {};
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8')) || {};
  } catch (err) {
    throw new Error(`Failed to parse config file ${configPath}: ${err.message}`);
  }
}

// Loads configuration, merging (lowest to highest precedence):
//   built-in defaults  <  JSON config file  <  environment variables
function loadConfig({ env = process.env } = {}) {
  const configPath = configPathFrom(env);
  const file = readConfigFile(configPath);

  const serverUrl = env.BLUEEYE_SERVER_URL || file.serverUrl || 'http://localhost:3000';
  // Alternative ways in to the SAME server, tried in order when the first cannot
  // be reached — a second DNS name, the internal address behind the proxy, a
  // spare ingress. One name or one reverse proxy is otherwise a single point of
  // failure that no amount of reconnecting gets past. `serverUrl` is always the
  // first candidate; the others are extras, never a different server (they share
  // the agent's token and its pins).
  const serverUrls = parseServerUrls(serverUrl, env.BLUEEYE_SERVER_URLS ?? file.serverUrls);
  const enrollmentCode = env.BLUEEYE_ENROLLMENT_CODE || file.enrollmentCode || null;
  // SHA-256 of the server's (or its reverse proxy's) TLS leaf cert. When set and
  // the server is https, the agent pins it and refuses a mismatching cert.
  // SEVERAL may be set (comma/space separated, or an array in the config file):
  // a pin is to one leaf certificate, so holding the NEXT certificate's pin
  // alongside the current one is what keeps a renewal from locking the fleet out
  // of the only channel that could fix it.
  const serverCertFingerprints = normalizeFingerprints(
    env.BLUEEYE_SERVER_CERT_FINGERPRINTS || env.BLUEEYE_SERVER_CERT_FINGERPRINT || file.serverCertFingerprints || file.serverCertFingerprint || ''
  );
  // The first pin, kept for the single-pin callers (the enroll CLI writes one,
  // doctor reports one) and for config files written by older agents.
  const serverCertFingerprint = serverCertFingerprints[0] || '';
  // Default is resolved relative to the agent's OWN directory, not the current
  // working directory — so a token written by `blueeye-agent enroll` is found by
  // the long-running service later even if they were started from different cwds
  // (e.g. enroll from /var/www, service from /opt/blueeye-agent). Override with
  // BLUEEYE_TOKEN_PATH (env) or tokenPath (config file).
  const tokenPath =
    env.BLUEEYE_TOKEN_PATH ||
    file.tokenPath ||
    path.join(__dirname, '..', '.blueeye-agent', 'token');
  const heartbeatMs = toInt(env.BLUEEYE_HEARTBEAT_MS, file.heartbeatMs ?? 15000);
  const backoff = {
    baseMs: toInt(env.BLUEEYE_RECONNECT_BASE_MS, file.reconnectBaseMs ?? 1000),
    maxMs: toInt(env.BLUEEYE_RECONNECT_MAX_MS, file.reconnectMaxMs ?? 30000),
    factor: 2,
  };
  // How long the agent tolerates hearing NOTHING back on an open socket before
  // it treats the connection as dead and re-dials. The heartbeat is a send; a
  // send says nothing about whether anything is still listening. Without this a
  // half-open TCP connection (a NAT table that dropped the entry, a firewall
  // that stopped forwarding, a load balancer that went away) leaves the agent
  // believing it is connected until the kernel gives up retransmitting —
  // typically 10-15 minutes on Linux, during which it is green in the dashboard,
  // takes no commands and loses its samples. 0 disables the check.
  const staleConnectionMs = toInt(env.BLUEEYE_STALE_CONNECTION_MS, file.staleConnectionMs ?? Math.max(3 * heartbeatMs, 30000));
  // TCP keepalive on the WebSocket socket, so the kernel also has a reason to
  // notice a path that stopped working. Belt to the stale-read braces above;
  // 0 disables it.
  const socketKeepAliveMs = toInt(env.BLUEEYE_SOCKET_KEEPALIVE_MS, file.socketKeepAliveMs ?? 30000);
  // How long to wait before re-dialling after the server REJECTED the token
  // (401). This used to be terminal — the agent exited and stayed down until
  // someone logged into the host. A revoked token deserves that; a server
  // restored from backup, a re-provisioned server or a rotated token does not,
  // and those take the whole fleet at once with no way in from the server side.
  // So a 401 now costs a long, quiet retry instead of the agent's life. It still
  // never re-enrolls by itself. 0 keeps the old behaviour (fatal, no retry).
  const authRetryMs = toInt(env.BLUEEYE_AUTH_RETRY_MS, file.authRetryMs ?? 900000);

  // Continuous reporting: how often the agent measures and submits traffic on
  // its own (0 disables it; default 60s). The sampling window per measurement
  // is reportSampleMs.
  const reportIntervalMs = toInt(env.BLUEEYE_REPORT_INTERVAL_MS, file.reportIntervalMs ?? 60000);
  const reportSampleMs = toInt(env.BLUEEYE_REPORT_SAMPLE_MS, file.reportSampleMs ?? 1000);
  // Measurements the server could not take are held here and re-submitted on the
  // next successful one, so a short outage leaves a gap in the DELIVERY rather
  // than a hole in the history. Bounded and oldest-first-dropped: an agent that
  // cannot reach its server for a day must not become the host's memory problem.
  // 0 disables the spool (drop on failure, the old behaviour).
  const resultSpoolMax = toInt(env.BLUEEYE_RESULT_SPOOL_MAX, file.resultSpoolMax ?? 240);
  // Local opt-out from the server's auto-update policy. The policy itself lives
  // on the server (off by default) and arrives with the agent config; this flag
  // lets one host refuse to act on it without the server having to know.
  const autoUpdateEnabled = toBool(env.BLUEEYE_AUTO_UPDATE, file.autoUpdate, true);

  // Scheduled active probes: the agent periodically pings its default gateway +
  // DNS servers (auto-discovered) and any configured targets, so fleet health is
  // populated without anyone triggering a probe. 0 disables it (default 60s).
  // Metadata only: reachability/timings, never payload.
  const probeIntervalMs = toInt(env.BLUEEYE_PROBE_INTERVAL_MS, file.probeIntervalMs ?? 60000);
  const probeCount = toInt(env.BLUEEYE_PROBE_COUNT, file.probeCount ?? 3);
  const probeAutoGateway = toBool(env.BLUEEYE_PROBE_GATEWAY, file.probeGateway, true);
  const probeAutoDns = toBool(env.BLUEEYE_PROBE_DNS, file.probeDns, true);
  const probeTargets = parseConfiguredTargets(env.BLUEEYE_PROBE_TARGETS ?? file.probeTargets);

  // Periodic capabilities re-report. The ARP table, connection table, NIC
  // inventory and LLDP neighbours ride on that report; without a cadence they
  // were only refreshed at start and on a WS reconnect. 0 disables it (default
  // 300 s — the server upserts, so a repeat costs a few rows, not duplicates).
  const capabilitiesIntervalMs = toInt(env.BLUEEYE_CAPABILITIES_INTERVAL_MS, file.capabilitiesIntervalMs ?? 300000);

  // Periodic re-fetch of GET /agents/me/config. The config used to be read only
  // at start and on a WS reconnect, so a switch assigned to a running agent, or
  // a changed traffic source, waited for the connection to drop. An unchanged
  // config applies as a no-op. 0 disables it (default 300 s).
  const configRefreshIntervalMs = toInt(env.BLUEEYE_CONFIG_REFRESH_MS, file.configRefreshIntervalMs ?? 300000);

  // Syslog receiver: the agent listens for the log messages switches, firewalls
  // and APs already emit, and forwards them to the server. Off by default — a
  // listening port is opt-in, never something an upgrade starts on its own.
  //
  // 1514, not 514: binding below 1024 needs root or CAP_NET_BIND_SERVICE, and
  // this agent must not run as root to receive untrusted UDP. A host that wants
  // the well-known port grants the capability to the service unit instead.
  const syslogEnabled = toBool(env.BLUEEYE_SYSLOG_ENABLED, file.syslogEnabled, false);
  const syslogPort = toInt(env.BLUEEYE_SYSLOG_PORT, file.syslogPort ?? 1514);
  const syslogBindAddress = env.BLUEEYE_SYSLOG_BIND || file.syslogBindAddress || '0.0.0.0';
  const syslogUdp = toBool(env.BLUEEYE_SYSLOG_UDP, file.syslogUdp, true);
  const syslogTcp = toBool(env.BLUEEYE_SYSLOG_TCP, file.syslogTcp, true);
  // How often buffered device events are flushed to the server. Independent of
  // reportIntervalMs: a link-down should not wait on a traffic sample.
  const syslogFlushIntervalMs = toInt(env.BLUEEYE_SYSLOG_FLUSH_MS, file.syslogFlushIntervalMs ?? 30000);
  const syslogMaxEvents = toInt(env.BLUEEYE_SYSLOG_MAX_EVENTS, file.syslogMaxEvents ?? 5000);
  const syslogRatePerSec = toInt(env.BLUEEYE_SYSLOG_RATE, file.syslogRatePerSec ?? 200);
  // Optional syslog sender allowlist: CIDRs / addresses (array in the file, or a
  // comma/space-separated env var). Empty = accept every sender, as before.
  // syslogOnlyPolled accepts the switches this agent polls over SNMP; with both
  // set, a sender either one vouches for is accepted. Parsed (and an invalid
  // entry reported) by the syslog receiver, which fails closed on it.
  const syslogAllowedSenders = toList(env.BLUEEYE_SYSLOG_ALLOWED_SENDERS ?? file.syslogAllowedSenders);
  const syslogOnlyPolled = toBool(env.BLUEEYE_SYSLOG_ONLY_POLLED, file.syslogOnlyPolled, false);

  // SNMP traps. Off by default like syslog, and 1162 rather than 162 for the
  // same reason: binding below 1024 needs root, and a monitoring agent must not
  // run as root to receive unauthenticated UDP. Traps share the device-event
  // flush with syslog, so they need no interval of their own.
  const trapsEnabled = toBool(env.BLUEEYE_TRAPS_ENABLED, file.trapsEnabled, false);
  const trapPort = toInt(env.BLUEEYE_TRAP_PORT, file.trapPort ?? 1162);
  const trapBindAddress = env.BLUEEYE_TRAP_BIND || file.trapBindAddress || '0.0.0.0';
  const trapMaxEvents = toInt(env.BLUEEYE_TRAP_MAX_EVENTS, file.trapMaxEvents ?? 2000);
  const trapRatePerSec = toInt(env.BLUEEYE_TRAP_RATE, file.trapRatePerSec ?? 50);
  // Refuse a v1/v2c trap whose community differs from the one the agent polls
  // that device with (only when that community is known). OFF by default: a
  // trap community that differs from the read community is a common, valid
  // setup, and refusing it would drop that device's traps without a trace.
  // Mismatches are always counted (`communityMismatch` in the trap stats).
  const trapsCheckCommunity = toBool(env.BLUEEYE_TRAPS_CHECK_COMMUNITY, file.trapsCheckCommunity, false);

  return {
    configPath,
    serverUrl,
    serverUrls,
    enrollmentCode,
    serverCertFingerprint,
    serverCertFingerprints,
    tokenPath,
    heartbeatMs,
    backoff,
    staleConnectionMs,
    socketKeepAliveMs,
    authRetryMs,
    reportIntervalMs,
    reportSampleMs,
    resultSpoolMax,
    autoUpdateEnabled,
    probeIntervalMs,
    probeCount,
    probeAutoGateway,
    probeAutoDns,
    probeTargets,
    capabilitiesIntervalMs,
    configRefreshIntervalMs,
    syslogEnabled,
    syslogPort,
    syslogBindAddress,
    syslogUdp,
    syslogTcp,
    syslogFlushIntervalMs,
    syslogMaxEvents,
    syslogRatePerSec,
    syslogAllowedSenders,
    syslogOnlyPolled,
    trapsEnabled,
    trapPort,
    trapBindAddress,
    trapMaxEvents,
    trapRatePerSec,
    trapsCheckCommunity,
  };
}

// Removes `enrollmentCode` from the JSON config file so the one-time code is
// not reused or left on disk. No-op when there is no config file or no code.
// (If the code was supplied purely via an env var it cannot be unset here — but
// once a token is stored the agent never enrolls again.)
function clearEnrollmentCode(config) {
  const { configPath } = config;
  if (!configPath || !fs.existsSync(configPath)) return false;
  const file = readConfigFile(configPath);
  if (!('enrollmentCode' in file)) return false;
  delete file.enrollmentCode;
  fs.writeFileSync(configPath, `${JSON.stringify(file, null, 2)}\n`);
  return true;
}

// Persists embedded server settings (serverUrl + cert fingerprint) into the
// JSON config file after enrollment, so the long-running service reaches the
// right server with pinning — the user never types the URL. Only writes keys
// with a value; creates the file if needed.
function writeConfigValues(config, values = {}) {
  const { configPath } = config;
  if (!configPath) return false;
  let file = {};
  if (fs.existsSync(configPath)) file = readConfigFile(configPath);
  let changed = false;
  for (const [k, v] of Object.entries(values)) {
    if (v === undefined || v === null || v === '') continue;
    if (file[k] !== v) { file[k] = v; changed = true; }
  }
  if (!changed && fs.existsSync(configPath)) return false;
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, `${JSON.stringify(file, null, 2)}\n`);
  return true;
}

// Builds the ordered list of server URLs to try. `primary` always leads (it is
// what enrollment, the pins and every existing deployment mean by "the server");
// `extra` may be an array or one string listing URLs separated by comma,
// semicolon or whitespace. Unparseable entries and duplicates are dropped, so a
// typo in the extras can never displace the URL that works.
function parseServerUrls(primary, extra) {
  const out = [];
  const add = (value) => {
    const url = String(value || '').trim().replace(/\/+$/, '');
    if (!url) return;
    try { new URL(url); } catch { return; }
    if (!out.includes(url)) out.push(url);
  };
  add(primary);
  const parts = Array.isArray(extra) ? extra : String(extra || '').split(/[\s,;]+/);
  for (const part of parts) add(part);
  return out;
}

module.exports = { loadConfig, clearEnrollmentCode, writeConfigValues, configPathFrom };
