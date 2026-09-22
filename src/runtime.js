'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand, isRunProbeCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand, isDiagnoseCommand, isDeleteCommand, isInstallToolCommand, isEvidenceCommand, isRunDiscoveryCommand, isRekeyCommand, isPollSnmpCommand, isBurstCommand, isStopBurstCommand } = require('./command');
const { createScanner, DiscoveryScopeError } = require('./discovery/scanner');
const { collectLocalCidrs } = require('./localIps');
const { createEvidenceCollector } = require('./evidenceCollector');
const { verifyManifest } = require('./release/verifyManifest');
const fs = require('fs');
const { createSelfUpdater } = require('./selfUpdate');
const { verifyCommand, requireSignedCommands, allowUnsignedRekey: allowUnsignedRekeyEnv } = require('./commandAuth');
const { createSelfDeleter } = require('./selfDelete');
const { createToolInstaller } = require('./toolInstaller');
const { createActionLog } = require('./actionLog');
const { resolveReleasePublicKey } = require('./release/publicKey');
const keyStore = require('./release/keyStore');
const releaseGuard = require('./release/releaseGuard');
const { verifyTrustProof } = require('./license/trustProof');
const { runSpeedtest } = require('./speedtest');
const { runTest } = require('./testRunner');
const { runProbe } = require('./probes');
const { resolveProbeTargets } = require('./probes/targets');
const { createSampler } = require('./monitor');
const { createHsflowdManager } = require('./sflow/hsflowd');
const { detectCapabilities } = require('./capabilities');
const { collectNicInfo } = require('./nicInfo');
const { collectConnections } = require('./connTable');
const { collectArpTable } = require('./arpTable');
const { collectLocalIps: collectLocalIpsDefault } = require('./localIps');
const { makePinnedFetch } = require('./httpsClient');
const path = require('path');
const { createSecretStore } = require('./transactions/secretStore');
const { createConfigStore } = require('./transactions/configStore');
const { createResultBuffer } = require('./transactions/buffer');
const { createTransactionManager } = require('./transactions/manager');
const { createSyslogReceiver } = require('./syslog/receiver');
const { createSnmpPoller } = require('./snmpPoller');
const { createTrapReceiver } = require('./traps/receiver');
const { createBurstRunner } = require('./burst');

// Hard cap on how many targets one scheduled cycle will probe, so a giant
// configured/nameserver list can't turn into a burst.
const MAX_SCHEDULED_TARGETS = 16;

// One-line, human-readable summary of a probe result for the info log.
function describeProbeOutcome(result) {
  if (!result.ok) return 'error';
  if (result.type === 'traceroute') {
    const hops = result.hopCount ?? (result.hops ? result.hops.length : '?');
    return `${hops} hops`;
  }
  return `${result.rttMs ?? '?'} ms`;
}

// Derives the hsflowd exporter options from the monitor config, or null when a
// local exporter isn't requested. A host self-provisions hsflowd only when the
// source is sflow AND `sflow.hsflowd` is set (true, or an options object) — so
// agents that receive sFlow from an external switch are unaffected.
function sflowExporterOptions(mc) {
  if (!mc || mc.source !== 'sflow' || !mc.sflow || !mc.sflow.hsflowd) return null;
  const h = typeof mc.sflow.hsflowd === 'object' ? mc.sflow.hsflowd : {};
  return {
    collectorPort: Number.isInteger(mc.sflow.port) ? mc.sflow.port : 6343,
    samplingRate: h.samplingRate,
    pollingSecs: h.pollingSecs,
    device: h.device,
  };
}

// Ties the WebSocket client and the REST client together:
//   - reports its capabilities and fetches its server-assigned monitor config
//     (which traffic source to use: proc or snmp);
//   - on a server "run test" command it measures + submits once;
//   - independently, it reports traffic on a fixed interval (continuous
//     reporting) so the server gets data without anyone triggering it.
// A token rejected over REST/WS (401) is fatal: it stops and does NOT re-enroll.
//
// Events: 'open', 'connected', 'close', 'results-submitted', 'command-ignored',
// 'command-error', 'config', 'fatal'. It never calls process.exit.
function createAgentRuntime({
  config,
  token,
  agentId,
  logger,
  fetchImpl = fetch,
  WebSocketImpl,
  samplerFactory = createSampler,
  capabilities = detectCapabilities(),
  probeRunner = runProbe,
  resolveTargets = resolveProbeTargets,
  collectNic = collectNicInfo,
  collectLocalIps = collectLocalIpsDefault,
  collectConns = collectConnections,
  collectArp = collectArpTable,
  discoveryScanner = createScanner(),
  collectCidrs = collectLocalCidrs,
  selfUpdater = null,
  selfDeleter = null,
  toolInstaller = null,
  actionLog = null,
  hsflowdManager = null,
  // Receives syslog from the network devices pointing at this host. Injectable
  // so tests drive it through ingestLine() without binding a port; null means
  // "build the real one if config.syslogEnabled".
  syslogReceiver = null,
  // Polls the switches the server assigned to THIS agent, alongside its own
  // traffic sampling. Injectable so tests drive runCycle() without net-snmp.
  snmpPoller = null,
  // Receives SNMP traps from those same switches. Injectable so tests drive
  // ingestDatagram() without binding a port or needing net-snmp.
  trapReceiver = null,
  // One-target, once-a-second measurement on command. Injectable so tests run
  // a two-minute burst against a fake clock.
  burstRunner = null,
  // Where a server-sent rekey stores this host's trust anchor (beside the token —
  // the one directory the agent is guaranteed to be able to write). Injectable.
  pinnedKeyPath = keyStore.pinnedKeyPath(config && config.tokenPath),
  keys = keyStore,
  // Blue/green layout + the guard that rolls a release back when it never
  // proves itself. Injectable so tests can point them at a scratch directory.
  releasesDir = process.env.BLUEEYE_RELEASES_DIR || '',
  guard = releaseGuard,
  confirmReleaseAfterMs = releaseGuard.DEFAULT_CONFIRM_MS,
  // The release trust anchor; injectable for tests. A key pinned here by an
  // accepted rekey wins over the one the installer baked into the environment.
  releasePublicKey = resolveReleasePublicKey(process.env, { pinnedPath: pinnedKeyPath, readPinned: (f) => keys.readPinnedKey(f) }),
  // Refuse a privileged command (update/delete/install-tool) that carries no
  // server signature. DEFAULTS ON wherever a release key is pinned — that agent
  // can check a signature and its server can make one, so accepting an unsigned
  // command would mean the WebSocket session alone is enough to reconfigure the
  // host. An agent with no key pinned stays lenient (nothing could verify
  // anything), and BLUEEYE_REQUIRE_SIGNED_COMMANDS overrides either way.
  // A RATCHET, not a fixed policy: leniency is dropped the first time this
  // server proves it can sign a command, and never comes back. Deriving it from
  // "a key is pinned" instead bricked every privileged command on a fleet whose
  // server had lost its signing key — see requireSignedCommands.
  strictCommands = requireSignedCommands(process.env, {
    signedBefore: keys.readTrustState(pinnedKeyPath).commandsSigned,
  }),
  // Break-glass: allow an UNSIGNED rekey to replace a trust anchor this host
  // already holds. Off by default — see the long note in src/commandAuth.js for
  // why rekey does not follow strictCommands' lenient default. Setting it needs
  // access to the host, which is the authority re-anchoring trust deserves.
  allowUnsignedRekey = allowUnsignedRekeyEnv(),
}) {
  const emitter = new EventEmitter();
  // The trust anchor in force RIGHT NOW. Mutable because a `rekey` command
  // replaces it while the agent runs: the update that follows it must verify
  // against the new key without waiting for a restart.
  let pinnedKey = releasePublicKey;
  const updater = selfUpdater || createSelfUpdater({ logger });
  // The deleter must wipe the token the runtime actually uses: tokenPath can be
  // set via the config FILE (not just env), and selfDelete's own default only
  // sees the env — so a file-configured path would be left un-wiped.
  const deleter = selfDeleter || createSelfDeleter({ logger, tokenPath: config.tokenPath });
  const installer = toolInstaller || createToolInstaller({ logger });
  // Local, server-independent action trail. Path comes from the env at
  // provisioning (BLUEEYE_ACTION_LOG); a no-op when unset. Never logs secrets.
  const actions = actionLog || createActionLog({ path: process.env.BLUEEYE_ACTION_LOG || '' });
  // When a cert fingerprint is configured and the server is https, pin it on the
  // REST calls too (the WS client pins separately). Falls back to the injected
  // fetch (or global fetch) otherwise — so tests that inject a fetch are unaffected.
  const fp = config.serverCertFingerprint;
  const effectiveFetch = (fp && /^https:/i.test(config.serverUrl)) ? makePinnedFetch(fp) : fetchImpl;
  const api = createApiClient({ serverUrl: config.serverUrl, token, fetchImpl: effectiveFetch });
  const client = createAgentClient({
    serverUrl: config.serverUrl,
    token,
    logger,
    heartbeatMs: config.heartbeatMs,
    backoff: config.backoff,
    WebSocketImpl,
    certFingerprint: fp,
  });

  // Transaction-test executor: runs server-pushed http/tcp/dns/icmp tests on their
  // own schedule (interval_sec ± 10% jitter), buffers results while offline (max
  // 1000, oldest dropped) and flushes on reconnect. Secrets are persisted
  // encrypted with a key derived from the token, and decrypted only in memory.
  const transactionConfigPath = config.transactionConfigPath
    || path.join(path.dirname(config.tokenPath || '.'), 'transactions.json');
  const txManager = createTransactionManager({
    send: (obj) => client.send(obj),
    configStore: createConfigStore({ filePath: transactionConfigPath, secretStore: createSecretStore(token), logger }),
    buffer: createResultBuffer({ max: 1000 }),
    logger,
  });
  client.on('transaction-config', (tests) => {
    try { txManager.applyConfig(tests); } catch (err) { logger.warn(`Failed to apply transaction config: ${err.message}`); }
  });

  // Syslog: built only when enabled, so a host that never turned it on binds
  // nothing and allocates nothing. An injected receiver always wins (tests).
  const syslog = syslogReceiver || (config.syslogEnabled
    ? createSyslogReceiver({
      port: config.syslogPort,
      bindAddress: config.syslogBindAddress,
      udp: config.syslogUdp,
      tcp: config.syslogTcp,
      maxEvents: config.syslogMaxEvents,
      ratePerSec: config.syslogRatePerSec,
      logger,
    })
    : null);
  let syslogTimer = null;
  let syslogBound = null; // what start() actually managed to bind, or null
  let lastDeviceEventAt = null; // ms epoch of the last successful flush

  // SNMP topology. Built unconditionally (it does nothing without targets) so
  // the server can start assigning switches to an already-running agent without
  // waiting for a restart.
  const snmp = snmpPoller || createSnmpPoller({
    submit: (payload) => api.postSnmpTopology(payload),
    submitCounters: (payload) => api.postSnmpCounters(payload),
    logger,
  });
  let snmpTargetCount = 0;
  let lastSnmpAt = null; // ms epoch of the last successful submit
  let lastSnmpCounterAt = null;

  // Interface names learned by the SNMP topology poll, keyed by the device's
  // address, so a trap saying "ifIndex 1" can be shown as "GigabitEthernet0/1".
  // Populated from the poll results the agent already submits; a device not in
  // here resolves to null and the trap shows the index, which is honest.
  const ifNamesByHost = new Map(); // host -> Map(ifIndex -> ifName)
  const hostByDeviceId = new Map();

  function rememberInterfaces(result) {
    const host = hostByDeviceId.get(result.deviceId);
    if (!host || !Array.isArray(result.interfaces)) return;
    const names = new Map();
    for (const i of result.interfaces) {
      if (Number.isInteger(i.ifIndex) && i.ifName) names.set(i.ifIndex, i.ifName);
    }
    if (names.size) ifNamesByHost.set(host, names);
  }

  function resolveTrapIfName(sourceIp, ifIndex) {
    const names = ifNamesByHost.get(sourceIp);
    return names ? (names.get(ifIndex) || null) : null;
  }

  // An SNMPv2c trap is unauthenticated: anyone who can route UDP here can claim
  // to be any switch. The source address is all we have, so a trap is accepted
  // only from an address this agent actually polls. Weak, and the strongest
  // check v2c permits.
  function isPolledSender(sourceIp) {
    return hostByDeviceId.size > 0 && [...hostByDeviceId.values()].includes(sourceIp);
  }

  // Traps: built only when enabled, like syslog. Shares the device-event flush,
  // because a trap and a syslog line are the same thing over a different socket.
  const traps = trapReceiver || (config.trapsEnabled
    ? createTrapReceiver({
      port: config.trapPort,
      bindAddress: config.trapBindAddress,
      maxEvents: config.trapMaxEvents,
      ratePerSec: config.trapRatePerSec,
      isKnownSender: isPolledSender,
      resolveIfName: resolveTrapIfName,
      logger,
    })
    : null);
  let trapsBound = null;

  // Burst mode. Built unconditionally: it binds nothing and allocates nothing
  // until a command arrives, and it is the one tool that must be available the
  // moment somebody is standing in front of a fault.
  const burst = burstRunner || createBurstRunner({ probeRunner, logger });

  let reportTimer = null;
  let reportingStarted = false; // true once the bootstrap called startReporting()
  let probeTimer = null;
  let fatal = false;
  let monitorConfig = { source: 'proc' };
  let currentSampler = samplerFactory(monitorConfig, { logger });
  let effectiveIntervalMs = config.reportIntervalMs;
  // Self-managed host sFlow exporter (hsflowd). Only acts when the monitor
  // source is sflow with a local exporter requested; on a containerised agent it
  // defers to the hsflowd sidecar.
  const hsflowd = hsflowdManager || createHsflowdManager({ runtime: capabilities.managed, logger });
  let hsflowdManaged = false;
  let lastHsflowdState = null;
  let lastReportAt = null; // ms epoch of the last successful results submission

  function handleFatal(reason = 'rest-token-rejected') {
    if (fatal) return;
    fatal = true;
    stopReporting();
    logger.error('Token rejected (HTTP 401); stopping. Will NOT re-enroll automatically.');
    client.stop();
    emitter.emit('fatal', reason);
  }

  // Ships a non-fatal operational error to the server over the live channel so it
  // surfaces in the server's audit trail (Reporting → Audit) — not just the local
  // log. Best-effort and metadata-only: a closed socket just drops it (the server
  // already infers offline), `category` lets the server collapse repeats onto one
  // row, and `message` is the Error text, never measured payload. A 401 is handled
  // by handleFatal, not reported here. Never throws.
  function reportError(category, err) {
    try {
      client.send({
        type: 'agent.error',
        category,
        code: (err && err.code) || null,
        message: err && err.message ? String(err.message).slice(0, 300) : 'error',
      });
    } catch { /* error reporting must never throw */ }
  }

  // Measures traffic (with the currently selected sampler) and submits it. A 401
  // is fatal; other errors are surfaced but non-terminal so the loop continues.
  async function runAndSubmit(command, source) {
    try {
      const result = await runTest(command, { sampler: currentSampler });
      const response = await api.postResults([result]);
      lastReportAt = Date.now();
      logger.info(`Traffic measured (${source}, ${monitorConfig.source}); results submitted.`);
      emitter.emit('results-submitted', { result, response, source });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') {
        handleFatal();
        return false;
      }
      logger.error(`Failed to measure/submit traffic (${source}): ${err.message}`);
      reportError('traffic-report', err);
      emitter.emit('command-error', err);
      return false;
    }
  }

  // Runs one active probe (ping/tcp/dns/traceroute) and submits the result. A
  // 401 is fatal; other errors are surfaced but non-terminal.
  //
  // A traceroute streams each hop over the WebSocket as the binary prints it
  // (`trace_hop`), so the dashboard draws the path while the trace runs. Only
  // for on-demand runs — scheduled traces have nobody watching. A dropped
  // frame costs one hop on the live view; the submitted result is the record.
  async function runProbeAndSubmit(probeSpec) {
    try {
      const result = await probeRunner(probeSpec, liveTraceDeps(probeSpec));
      const response = await api.postProbeResults([result]);
      const outcome = describeProbeOutcome(result);
      logger.info(`Probe ${result.type} → ${result.target}: ${outcome}.`);
      emitter.emit('probe-submitted', { result, response });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return false; }
      logger.error(`Failed to run/submit probe: ${err.message}`);
      reportError('probe', err);
      emitter.emit('command-error', err);
      return false;
    }
  }

  function liveTraceDeps(spec) {
    const probeType = String((spec && spec.type) || '').toLowerCase();
    if (probeType !== 'traceroute' && probeType !== 'tcptraceroute') return undefined;
    const host = String((spec && (spec.host || spec.target)) || '').trim();
    // The same target string the finished result carries, so the dashboard
    // can match a hop to the trace it is waiting on.
    const target = probeType === 'tcptraceroute' ? `${host}:${spec.port !== undefined ? spec.port : 443}` : host;
    const onHop = (hop) => {
      try { client.send({ type: 'trace_hop', probeType, target, hop }); } catch { /* not connected */ }
    };
    return { [probeType]: { onHop } };
  }

  // Runs an active-discovery sweep from THIS agent's vantage and reports the
  // candidates. Scope resolution: the server-provided CIDRs, or — when empty —
  // this host's own subnet(s) ("scan the segment I'm on"). The scanner enforces
  // the address cap + scope guard and refuses an empty/over-cap scope (reported
  // back as a refusal, not a crash). Native probes only; never a write action.
  async function runDiscoveryAndSubmit(spec) {
    const d = spec && typeof spec === 'object' ? spec : {};
    const requestId = d.requestId != null ? d.requestId : null;
    let cidrs = Array.isArray(d.cidrs) ? d.cidrs.map((c) => String(c).trim()).filter(Boolean) : [];
    let derivedFromSelf = false;
    if (!cidrs.length) { cidrs = collectCidrs(); derivedFromSelf = true; }
    const startedAt = new Date().toISOString();
    try {
      const result = await discoveryScanner.scan({
        cidrs,
        addressCap: d.addressCap != null ? Number(d.addressCap) : 65536,
        ratePerSec: d.rateLimit != null ? Number(d.rateLimit) : 50,
        portList: Array.isArray(d.ports) && d.ports.length ? d.ports.map(Number).filter((n) => n > 0) : undefined,
      });
      const payload = {
        requestId,
        scope: cidrs,
        derivedFromSelf,
        addresses: result.addresses,
        probed: result.probed.length,
        candidates: result.candidates,
        startedAt,
        endedAt: new Date().toISOString(),
      };
      await api.postDiscoveryResults(payload);
      logger.info(`Discovery swept ${result.addresses} addr(s) in ${cidrs.join(', ') || '(none)'} → ${result.candidates.length} candidate(s).`);
      emitter.emit('discovery-submitted', payload);
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return false; }
      // A scope refusal is an expected outcome, not an error — report it so the
      // server can audit "refused (reason)" instead of the sweep vanishing.
      if (err instanceof DiscoveryScopeError) {
        try {
          await api.postDiscoveryResults({ requestId, scope: cidrs, derivedFromSelf, refused: true, reason: err.code, candidates: [], startedAt, endedAt: new Date().toISOString() });
        } catch { /* best-effort */ }
        logger.warn(`Discovery refused: ${err.code}.`);
        emitter.emit('discovery-refused', { reason: err.code });
        return false;
      }
      logger.error(`Failed to run/submit discovery: ${err.message}`);
      reportError('discovery', err);
      emitter.emit('command-error', err);
      return false;
    }
  }

  // Reports capabilities to the server. Resilient: only a 401 is fatal. NIC
  // inventory (driver/firmware per interface) is collected best-effort and
  // folded in, so the server can spot fleet-wide firmware drift; a failure to
  // read it just omits the field.
  async function reportCapabilities() {
    let payload = capabilities;
    try {
      const nic = await collectNic();
      // ...payload, not ...capabilities: every block below extends what the one
      // before it built, and rebuilding from the base here silently dropped
      // whatever had already been added.
      if (Array.isArray(nic) && nic.length) payload = { ...payload, nic };
    } catch { /* NIC inventory is best-effort */ }
    try {
      const ips = collectLocalIps();
      if (Array.isArray(ips) && ips.length) payload = { ...payload, ips };
    } catch { /* own-IP list is best-effort */ }
    try {
      // Established-TCP connection table → directed service-dependency edges, so a
      // proc/snmp-only host (no NetFlow/sFlow) still feeds the server's graph.
      const connections = await collectConns();
      if (Array.isArray(connections) && connections.length) payload = { ...payload, connections };
    } catch { /* connection table is best-effort */ }
    try {
      // ARP/neighbour table → the server's IP<->MAC identity source, so a
      // technician can search for the address they were told instead of a
      // hostname they have to look up first. Metadata only.
      const arp = await collectArp();
      if (Array.isArray(arp) && arp.length) payload = { ...payload, arp };
    } catch { /* neighbour table is best-effort */ }
    // WHICH KEY THIS AGENT TRUSTS. A fingerprint of the PUBLIC release key it
    // pins — never the key, never a secret, and the one fact that turns
    // "refused: command signature verification failed" from a mystery into a
    // sentence: this agent trusts ab12…, this server signs with cd34…, so
    // re-pin it. Without it the dashboard can see THAT an agent refuses every
    // signed command and not WHY, and nobody can look: these hosts have no
    // shell. Added last so a later rekey is reflected on the next report.
    try {
      payload = { ...payload, releaseKeyFingerprint: pinnedKey ? keys.fingerprintOf(pinnedKey) : null };
    } catch { /* a diagnostic is never a reason to fail the report it rides on */ }
    try {
      await api.postCapabilities(payload);
      const nicNote = payload.nic ? ` + ${payload.nic.length} NIC(s)` : '';
      const connNote = payload.connections ? ` + ${payload.connections.length} conn edge(s)` : '';
      const arpNote = payload.arp ? ` + ${payload.arp.length} ARP entr(ies)` : '';
      logger.info(`Reported capabilities: ${capabilities.sources.join(', ') || '(none)'}${nicNote}${connNote}${arpNote}`);
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return; }
      logger.warn(`Could not report capabilities (${err.message}).`);
      reportError('capabilities', err);
    }
  }

  // Fetches the server-assigned monitor config and rebuilds the sampler.
  // Resilient: only a 401 is fatal; otherwise keep the current source.
  async function loadServerConfig() {
    try {
      // The WHOLE body, not just monitorConfig: the same call now also carries
      // `snmpTargets`, the switches this agent polls. Reading it here means a
      // switch assigned to a running agent is picked up on its next reconnect
      // rather than waiting for a restart.
      const body = await api.getFullConfig();
      const mc = (body && body.monitorConfig) || { source: 'proc' };
      applySnmpTargets(body && body.snmpTargets);
      monitorConfig = mc;
      // Dispose the previous sampler's background lifecycle (e.g. a netflow
      // UDP socket) before swapping in the new source.
      if (currentSampler && typeof currentSampler.stop === 'function') currentSampler.stop();
      currentSampler = samplerFactory(monitorConfig, { logger });
      const prevIntervalMs = effectiveIntervalMs;
      effectiveIntervalMs =
        Number.isInteger(mc.intervalMs) && mc.intervalMs > 0 ? mc.intervalMs : config.reportIntervalMs;
      logger.info(`Monitor source: ${monitorConfig.source} (report every ${effectiveIntervalMs}ms).`);
      emitter.emit('config', monitorConfig);
      // A reconnect can carry a changed reporting interval; the bootstrap timer
      // keeps its old cadence unless restarted here. Only after the bootstrap
      // has started reporting — during bootstrap loadServerConfig() runs first
      // and startReporting() follows right after.
      if (reportingStarted && effectiveIntervalMs !== prevIntervalMs) {
        stopReporting();
        startReporting();
      }
      await reconcileHsflowd();
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return; }
      logger.warn(`Could not fetch monitor config (${err.message}); using ${monitorConfig.source}.`);
      reportError('config', err);
    }
  }

  // Was the host's hsflowd provisioned by this agent — now, or by a PREVIOUS
  // process? The in-memory flag dies with a restart; the manager re-derives it
  // from the conf marker. Injected test fakes without isManaged() mean "no".
  // Never throws.
  async function managedByThisAgent() {
    try {
      return typeof hsflowd.isManaged === 'function' ? !!(await hsflowd.isManaged()) : false;
    } catch { return false; }
  }

  // Converges the local hsflowd exporter to the server's desired state. Runs on
  // every config load — i.e. at startup and on each WS reconnect — so the host
  // re-reconciles whenever it reconnects. Never throws (the manager swallows OS
  // errors and reports a state instead).
  async function reconcileHsflowd() {
    const opts = sflowExporterOptions(monitorConfig);
    let r = null;
    if (opts) {
      r = await hsflowd.enable(opts);
      hsflowdManaged = true;
    } else if (hsflowdManaged || (await managedByThisAgent())) {
      // The source moved away from sflow (or the exporter was switched off) and
      // we were managing it — possibly in a previous process: the conf marker
      // outlives a restart, so the exporter doesn't end up orphaned. Stop it,
      // but leave it installed for a fast re-enable.
      r = await hsflowd.disable();
      hsflowdManaged = false;
    }
    if (!r) return;
    lastHsflowdState = r;
    logger.info(`hsflowd: ${r.state}${r.detail ? ` (${r.detail})` : ''}.`);
    emitter.emit('hsflowd', r);
    // Report the observed state to the server (best-effort) so the dashboard can
    // show whether the exporter actually came up after an enable/disable. If the
    // socket isn't open it's re-sent on the next reconnect (reconcile runs then).
    try { client.send({ type: 'sflow.status', state: r.state, detail: r.detail || null }); } catch { /* not connected */ }
  }

  function startReporting() {
    if (fatal) return;
    reportingStarted = true;
    if (!effectiveIntervalMs || effectiveIntervalMs <= 0) {
      logger.info('Continuous reporting disabled (interval <= 0).');
      return;
    }
    stopReporting();
    const command = { name: 'auto-report', intervalMs: config.reportSampleMs };
    logger.info(`Continuous reporting every ${effectiveIntervalMs}ms (sample ${config.reportSampleMs}ms).`);
    let running = false;
    reportTimer = setInterval(async () => {
      if (fatal || running) return;
      running = true;
      try {
        await runAndSubmit(command, 'auto');
      } finally {
        running = false;
      }
    }, effectiveIntervalMs);
    if (reportTimer.unref) reportTimer.unref();
  }

  function stopReporting() {
    if (reportTimer) {
      clearInterval(reportTimer);
      reportTimer = null;
    }
  }

  // Drains the syslog buffer and ships one batch. A 401 is fatal; anything else
  // is non-terminal — but the drained events are NOT put back. A server that is
  // down for an hour would otherwise have the agent hold an hour of log lines in
  // memory on a host it does not own, and the receiver's own bounded buffer
  // exists precisely so this process never becomes the outage. The counters in
  // stats() record what was lost, so the gap is visible rather than silent.
  async function flushDeviceEvents() {
    if (fatal || (!syslog && !traps)) return 0;
    // Both receivers drain into ONE batch: a trap and a syslog line are the
    // same kind of row, and sending them separately would double the requests
    // for no benefit. A receiver that throws costs its own rows, not the
    // other's.
    const events = [];
    for (const [name, rx] of [['syslog', syslog], ['traps', traps]]) {
      if (!rx) continue;
      try {
        events.push(...rx.drain());
      } catch (err) {
        logger.warn(`Could not drain the ${name} buffer (${err.message}).`);
      }
    }
    if (!events.length) return 0;
    try {
      await api.postDeviceEvents(events);
      lastDeviceEventAt = Date.now();
      logger.info(`Submitted ${events.length} device event(s).`);
      emitter.emit('device-events', events.length);
      return events.length;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return 0; }
      logger.warn(`Could not submit ${events.length} device event(s) (${err.message}).`);
      reportError('device-events', err);
      return 0;
    }
  }

  // Binds the receiver and starts the flush timer. A bind failure is reported
  // and survived: the agent's traffic reporting and probes must keep working on
  // a host where something else already holds the port.
  async function startSyslog() {
    if (!syslog || fatal) return;
    try {
      syslogBound = typeof syslog.start === 'function' ? await syslog.start() : { injected: true };
      emitter.emit('syslog', syslogBound);
    } catch (err) {
      logger.warn(`Syslog receiver did not start (${err.message}).`);
      reportError('syslog-bind', err);
      emitter.emit('syslog', null);
      return;
    }
    const intervalMs = config.syslogFlushIntervalMs;
    if (!intervalMs || intervalMs <= 0) return;
    let running = false;
    syslogTimer = setInterval(async () => {
      if (fatal || running) return;
      running = true;
      try {
        await flushDeviceEvents();
      } finally {
        running = false;
      }
    }, intervalMs);
    if (syslogTimer.unref) syslogTimer.unref();
  }

  // Applies the server's switch assignment. An agent whose server is too old to
  // send the key gets an empty list and polls nothing, which is exactly right.
  function applySnmpTargets(list) {
    try {
      snmpTargetCount = snmp.setTargets(list);
      // The trap allowlist and the ifIndex resolver both key on the device's
      // address, so they are rebuilt from the same assignment.
      hostByDeviceId.clear();
      for (const d of Array.isArray(list) ? list : []) {
        if (d && d.deviceId != null && typeof d.host === 'string') hostByDeviceId.set(d.deviceId, d.host);
      }
      if (snmpTargetCount) logger.info(`SNMP topology: polling ${snmpTargetCount} device(s).`);
    } catch (err) {
      logger.warn(`Could not apply SNMP targets (${err.message}).`);
      snmpTargetCount = 0;
    }
  }

  // Runs one poll cycle. A 401 is fatal like everywhere else; anything else is
  // non-terminal — a switch that did not answer is reported as a per-device
  // error inside the batch, not as a failure of the cycle.
  // Runs a burst and streams every sample over the WebSocket the agent already
  // holds, so the dashboard's chart draws while the measurement happens rather
  // than appearing whole at the end. A dropped frame costs one point on a
  // chart; the authoritative series is in the final reply.
  async function handleBurst(command) {
    const id = command && command.id;
    const result = await burst.run(command, {
      onSample: (sample, progress) => {
        try {
          client.send({ type: 'burst_sample', id, sample, index: progress.index, total: progress.total });
        } catch { /* the chart is a courtesy; the reply is the record */ }
      },
    });
    client.send({ type: 'command-result', id, ok: result.ok, burst: result });
    emitter.emit('burst', result);
    return result;
  }

  async function runSnmpCycle(opts) {
    if (fatal || !snmpTargetCount) return { polled: 0, failed: 0 };
    try {
      const r = await snmp.runCycle({ ...(opts || {}), onResult: rememberInterfaces });
      if (r.polled) {
        lastSnmpAt = Date.now();
        emitter.emit('snmp-topology', r);
      }
      return r;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return { polled: 0, failed: 0 }; }
      logger.warn(`SNMP topology cycle failed (${err.message}).`);
      reportError('snmp-topology', err);
      return { polled: 0, failed: 0 };
    }
  }

  // The counter cycle, on its own schedule. Separate from runSnmpCycle because
  // the two measure different things at different cadences: a forwarding table
  // is a snapshot of where things are, and a counter series' interval IS its
  // resolution.
  async function runSnmpCounterCycle(opts) {
    if (fatal || !snmpTargetCount) return { polled: 0, failed: 0 };
    try {
      const r = await snmp.runCounterCycle(opts || {});
      if (r.polled) {
        lastSnmpCounterAt = Date.now();
        emitter.emit('snmp-counters', r);
      }
      return r;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return { polled: 0, failed: 0 }; }
      logger.warn(`SNMP counter cycle failed (${err.message}).`);
      reportError('snmp-counters', err);
      return { polled: 0, failed: 0 };
    }
  }

  // Binds the trap receiver. Like syslog, a failure here is reported and
  // survived: an agent that cannot bind 1162 must keep reporting traffic,
  // running probes and polling switches.
  async function startTraps() {
    if (!traps || fatal) return;
    try {
      trapsBound = typeof traps.start === 'function' ? await traps.start() : { injected: true };
      emitter.emit('traps', trapsBound);
    } catch (err) {
      logger.warn(`SNMP trap receiver did not start (${err.message}).`);
      reportError('trap-bind', err);
      emitter.emit('traps', null);
    }
  }

  function stopTraps() {
    if (traps && typeof traps.stop === 'function') {
      try { traps.stop(); } catch { /* shutdown must not throw */ }
    }
    trapsBound = null;
  }

  function stopSyslog() {
    if (syslogTimer) {
      clearInterval(syslogTimer);
      syslogTimer = null;
    }
    if (syslog && typeof syslog.stop === 'function') {
      try { syslog.stop(); } catch { /* shutdown must not throw */ }
    }
    syslogBound = null;
  }

  // Resolves the scheduled probe set (gateway + DNS + configured), runs each and
  // submits the batch in one POST. A 401 is fatal; other errors are non-terminal.
  // runProbe never throws, so a single bad target can't abort the cycle.
  async function runScheduledProbes() {
    if (fatal) return false;
    let specs;
    try {
      specs = await resolveTargets({
        configured: config.probeTargets,
        gateway: config.probeAutoGateway,
        dns: config.probeAutoDns,
        count: config.probeCount,
      });
    } catch (err) {
      logger.warn(`Could not resolve probe targets (${err.message}).`);
      reportError('probe-targets', err);
      return false;
    }
    if (!specs || !specs.length) return false;
    const results = [];
    for (const spec of specs.slice(0, MAX_SCHEDULED_TARGETS)) {
      results.push(await probeRunner(spec));
    }
    try {
      const response = await api.postProbeResults(results);
      logger.info(`Scheduled probes: ${results.length} target(s) submitted.`);
      emitter.emit('scheduled-probes-submitted', { results, response });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return false; }
      logger.error(`Failed to submit scheduled probes: ${err.message}`);
      reportError('scheduled-probes', err);
      emitter.emit('command-error', err);
      return false;
    }
  }

  function startScheduledProbes() {
    if (fatal) return;
    if (!config.probeIntervalMs || config.probeIntervalMs <= 0) {
      logger.info('Scheduled probes disabled (interval <= 0).');
      return;
    }
    stopScheduledProbes();
    logger.info(`Scheduled probes every ${config.probeIntervalMs}ms (gateway/DNS + ${config.probeTargets.length} configured).`);
    let running = false;
    probeTimer = setInterval(async () => {
      if (fatal || running) return;
      running = true;
      try { await runScheduledProbes(); } finally { running = false; }
    }, config.probeIntervalMs);
    if (probeTimer.unref) probeTimer.unref();
  }

  function stopScheduledProbes() {
    if (probeTimer) {
      clearInterval(probeTimer);
      probeTimer = null;
    }
  }

  client.on('open', () => {
    emitter.emit('open');
    // On (re)connect, re-report capabilities AND refresh config. Re-reporting
    // capabilities converges the server's stored agent version onto the running
    // one — after a self-update/restart, or when the one-shot bootstrap report
    // raced a server restart and never landed. Without this the dashboard's
    // overview keeps showing the stale version (and a phantom "update" badge)
    // even though the live agent — and the Diagnose snapshot — is newer.
    if (!fatal) {
      reportCapabilities().catch(() => {});
      loadServerConfig().catch(() => {});
      // Flush any transaction results buffered while we were offline.
      try { txManager.flush(); } catch (err) { logger.warn(`Transaction flush failed: ${err.message}`); }
    }
  });
  // Confirming an update is the agent's job, and "connected" alone is not
  // enough: a release that comes up, connects and then dies on its first real
  // work would confirm the very thing killing it. So the timer starts on the
  // first connection and only a connection that HOLDS clears the marker. Until
  // it does, the release guard counts this release's starts and rolls back.
  let confirmTimer = null;
  function armReleaseConfirmation() {
    if (confirmTimer || !releasesDir) return;
    const pending = guard.readPending(releasesDir);
    if (!pending) return; // no update waiting to prove itself
    logger.info(`Release ${pending.version} is unproven (start ${pending.attempts}); confirming after ${Math.round(confirmReleaseAfterMs / 1000)}s connected.`);
    confirmTimer = setTimeout(() => {
      confirmTimer = null;
      if (guard.confirmRelease(releasesDir)) {
        actions.log('update.confirmed', { version: pending.version });
        logger.info(`Release ${pending.version} confirmed — it held a server connection.`);
        emitter.emit('release-confirmed', pending);
      }
    }, confirmReleaseAfterMs);
    if (typeof confirmTimer.unref === 'function') confirmTimer.unref();
  }

  client.on('connected', (m) => { armReleaseConfirmation(); emitter.emit('connected', m); });
  client.on('close', (code) => emitter.emit('close', code));
  // A WS-origin fatal (e.g. 401 handshake) must fully shut the runtime down too
  // — stop reporting + mark fatal — not just re-emit, so no timers linger.
  client.on('fatal', (reason) => handleFatal(reason));

  // Snapshot of this agent's flow pipeline for the dashboard "Diagnose" action:
  // the live monitor source, the collector's receive/decode counters (read
  // WITHOUT draining them, so a diagnose never steals an interval's data), the
  // local exporter state and when we last reported. Pure read of current state.
  function buildDiagnostic() {
    const stats = currentSampler && typeof currentSampler.stats === 'function' ? currentSampler.stats() : null;
    const kind = currentSampler ? currentSampler.kind || null : null;
    return {
      agentVersion: capabilities.agentVersion,
      managed: capabilities.managed,
      source: monitorConfig.source,
      sources: capabilities.sources,
      intervalMs: effectiveIntervalMs,
      lastReportAt: lastReportAt ? new Date(lastReportAt).toISOString() : null,
      collector: stats ? { kind, ...stats } : null,
      hsflowd: lastHsflowdState ? { state: lastHsflowdState.state, detail: lastHsflowdState.detail || null } : null,
      // Same question as the flow pipeline, one layer over: are device events
      // arriving at all, are they being refused by the rate limit, and is the
      // buffer overflowing? Answerable from the dashboard, without host access.
      syslog: syslog && typeof syslog.stats === 'function'
        ? {
          ...syslog.stats(),
          bound: syslogBound,
          lastSubmitAt: lastDeviceEventAt ? new Date(lastDeviceEventAt).toISOString() : null,
        }
        : null,
      traps: traps && typeof traps.stats === 'function'
        ? { ...traps.stats(), bound: trapsBound }
        : null,
      // Which switches this agent polls, when each was last attempted, and
      // whether anything has been submitted. Answers "why is this switch's
      // port table empty?" from the dashboard, without host access.
      snmp: snmpTargetCount
        ? {
          ...snmp.stats(),
          lastSubmitAt: lastSnmpAt ? new Date(lastSnmpAt).toISOString() : null,
          // Reported separately: a fleet where the topology poll works and the
          // counter poll does not is a real and very different state from one
          // where neither does.
          lastCounterSubmitAt: lastSnmpCounterAt ? new Date(lastSnmpCounterAt).toISOString() : null,
        }
        : null,
    };
  }

  // Replies to a server "diagnose" command with the snapshot above, so the
  // dashboard can show, per agent, exactly where flows stop (source isn't a flow
  // source, no datagrams arriving, datagrams but no flow samples, exporter down).
  function handleDiagnose(command) {
    const diagnostic = buildDiagnostic();
    client.send({ type: 'command-result', id: command && command.id, ok: true, diagnostic });
    emitter.emit('diagnosed', diagnostic);
  }

  // Replies to a server "ping" with this agent's live identity, so the dashboard
  // can confirm the round-trip works (not just that a row says "online").
  function handlePing(command) {
    client.send({
      type: 'ack',
      id: command && command.id,
      ok: true,
      agentVersion: capabilities.agentVersion,
      sources: capabilities.sources,
      managed: capabilities.managed,
    });
    emitter.emit('pinged', command);
  }

  // Gate for the PRIVILEGED commands (update / delete / install-tool) — the three
  // that change the host rather than measure it. A command carrying a server
  // signature must verify against the pinned release key; in strict mode an
  // unsigned one is refused outright. Refusals are reported on the same channels
  // the handlers use (ack + command-result + the audit row), so the operator sees
  // a declined action rather than silence. Returns false when the command must
  // not run. `names.log` is the local action-log prefix, `names.audit` the
  // server's action name (which is 'upgrade' where the wire says 'update').
  function authorizeCommand(command, names) {
    // `rekey` does not follow the lenient default — it replaces the trust
    // anchor every later signature is checked against. See src/commandAuth.js.
    const verdict = verifyCommand(command, {
      publicKey: pinnedKey,
      agentId,
      strict: strictCommands,
      isRekey: names.log === 'rekey',
      allowUnsignedRekeyOverride: allowUnsignedRekey,
    });
    if (verdict.ok) {
      // The server just proved it can sign. Latch it: from now on an unsigned
      // privileged command is refused, on this run and every later one. An
      // attacker holding the socket cannot un-ring that bell.
      if (verdict.signed && !strictCommands && keys.markCommandsSigned(pinnedKeyPath)) {
        strictCommands = true;
        logger.info('This server signs privileged commands — unsigned ones are refused from now on.');
        actions.log('commands.signature-required', {});
      }
      return true;
    }
    const auditId = command && command.auditId;
    actions.log(`${names.log}.refused`, { reason: verdict.reason });
    logger.error(`Refusing ${names.log} command: ${verdict.reason}`);
    client.send({ type: 'ack', id: command && command.id, accepted: false, reason: verdict.reason });
    client.send({ type: 'command-result', id: command && command.id, ok: false, error: verdict.reason });
    if (auditId != null) client.send({ type: 'action-result', auditId, action: names.audit, ok: false, detail: verdict.reason });
    emitter.emit('command-refused', { action: names.log, reason: verdict.reason });
    return false;
  }

  // Handles a server "update" command: acknowledge immediately (so the dashboard
  // learns whether we can self-update), then — only when systemd-managed —
  // rebuild from the server's verified source bundle and restart. Docker and
  // unmanaged agents decline; their host rebuilds them.
  async function handleUpdate(command) {
    if (!authorizeCommand(command, { log: 'update', audit: 'upgrade' })) return;
    const managed = capabilities.managed;
    const auditId = command && command.auditId;
    if (managed !== 'systemd') {
      const reason = managed === 'docker' ? 'docker-managed' : 'unmanaged';
      client.send({ type: 'ack', id: command && command.id, accepted: false, runtime: managed || 'unmanaged', reason });
      actions.log('update.declined', { runtime: managed || 'unmanaged', reason });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: false, detail: reason });
      logger.warn(`Ignoring update command: runtime '${managed}' is not self-updatable (systemd only).`);
      emitter.emit('update-skipped', { managed, reason });
      return;
    }
    client.send({ type: 'ack', id: command && command.id, accepted: true, runtime: 'systemd' });
    const targetVersion = (command && command.version) || null;
    const signed = !!(command && command.signature);
    actions.log('update.start', { version: targetVersion, signed });
    logger.info(`Update accepted; downloading and ${signed ? 'verifying the signed release' : 'rebuilding from the server source'}...`);
    try {
      await updater.update({
        serverUrl: config.serverUrl,
        token,
        expectedSha: command && command.sha256,
        expectedVersion: targetVersion,
        signature: command && command.signature,
        publicKey: pinnedKey,
        fetchImpl: effectiveFetch,
      });
      actions.log('update.applied', { version: targetVersion });
      logger.info('Update applied; requesting service restart.');
      // Report completion BEFORE restarting — once systemd swaps us we can't speak.
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: true, version: targetVersion });
      emitter.emit('update-applied');
      // systemd stops us (SIGTERM -> graceful exit) then starts the new code.
      // If it does NOT, we are still the old process running the old code: the
      // new version is on disk, this agent keeps reporting the old one, and the
      // dashboard would show an update that "worked" for ever. We are still alive
      // to say so, so correct the outcome we just reported.
      const restarted = updater.restart();
      if (restarted && restarted.ok === false) {
        const unit = process.env.BLUEEYE_SERVICE_NAME || 'blueeye-agent';
        const detail = `installed v${targetVersion || '?'} but the service restart failed (${restarted.detail}) — run: systemctl restart ${unit}`;
        actions.log('update.restart-failed', { version: targetVersion, error: restarted.detail });
        logger.error(`Self-update: ${detail}`);
        client.send({ type: 'command-result', id: command && command.id, ok: false, error: detail });
        if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: false, detail });
        emitter.emit('update-error', new Error(detail));
      }
    } catch (err) {
      actions.log('update.failed', { version: targetVersion, error: err.message });
      logger.error(`Self-update failed: ${err.message}`);
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: err.message });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: false, detail: err.message });
      emitter.emit('update-error', err);
    }
  }

  // Handles a server "rekey" command: replace the release trust anchor this host
  // pins for signed self-updates, and keep it across restarts.
  //
  // Why the server may do this at all. The anchor is what stops a compromised
  // server pushing code this agent would run — but the agent took it from that
  // same server at install time (trust-on-first-use), and the same channel
  // already carries `delete`, which removes the agent outright. So accepting a
  // rekey over the authenticated link is no weaker than what is already
  // accepted there, and it is the only way to recover a fleet whose server lost
  // its signing key: there is no shell on these hosts. When the server CAN still
  // sign, the command carries a commandSignature made with the key being
  // replaced — a proper rotation, verified by authorizeCommand below — and
  // BLUEEYE_REQUIRE_SIGNED_COMMANDS=1 makes that mandatory.
  //
  // Not a restart: the new anchor is applied in memory, so the update that
  // usually follows it verifies immediately, and monitoring never stops.
  // Records what the vendor authorised, which also LATCHES this agent: from
  // here on a rekey without a vendor authorisation is refused. Best-effort on
  // the write — a failure means the latch is not yet set, which only ever asks
  // for more proof later, never less.
  function recordVendorTrust(verdict) {
    keys.writeTrustState(pinnedKeyPath, {
      sequence: verdict.sequence,
      licenseId: verdict.licenseId,
      customerId: verdict.customerId,
      fingerprint: verdict.fingerprint,
    });
  }

  async function handleRekey(command) {
    const auditId = command && command.auditId;

    // What this host has already accepted from the vendor. `vendorRooted` is a
    // one-way latch: once a vendor-authorised key has been accepted here,
    // nothing else is ever accepted again, and no server can clear it.
    const trustState = keys.readTrustState(pinnedKeyPath);

    // The vendor's authorisation, if the server sent one. This is the ONLY
    // check that can accept a key this agent has never seen: the signature is
    // the vendor's, over bytes the server can neither forge nor edit, so a
    // server that has been taken over cannot manufacture one.
    let vendor = null;
    if (command && command.vendorProof) {
      const verdict = verifyTrustProof({
        proof: command.vendorProof,
        offeredKey: command.publicKey,
        expected: {
          licenseId: trustState.licenseId,
          customerId: trustState.customerId,
          sequence: trustState.sequence,
        },
      });
      if (!verdict.ok) {
        // Fail closed and say which step failed — these codes are what an
        // operator reads when a rekey does not land.
        const reason = `refusing rekey: ${verdict.code} — ${verdict.detail}`;
        actions.log('rekey.refused', { code: verdict.code, reason: verdict.detail });
        logger.error(reason);
        client.send({ type: 'ack', id: command && command.id, accepted: false, reason });
        client.send({ type: 'command-result', id: command && command.id, ok: false, error: reason });
        if (auditId != null) client.send({ type: 'action-result', auditId, action: 'rekey', ok: false, detail: reason });
        emitter.emit('rekey-error', new Error(reason));
        return;
      }
      vendor = verdict;
    } else if (trustState.vendorRooted) {
      // Latched. A rekey signed with the key being replaced was the migration
      // path; once the vendor has spoken for this host, that path is closed —
      // otherwise an attacker who obtained the old private key could still
      // re-anchor the fleet.
      const reason = 'refusing rekey: this agent requires a vendor-signed authorisation, and the command carried none. '
        + 'The server must obtain a licence proof authorising this key (its administrator generates the key, '
        + 'the vendor approves the fingerprint) before the fleet will accept it.';
      actions.log('rekey.refused', { code: 'LICENSE_PROOF_INVALID', reason: 'no vendor proof' });
      logger.error(reason);
      client.send({ type: 'ack', id: command && command.id, accepted: false, reason });
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: reason });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'rekey', ok: false, detail: reason });
      emitter.emit('rekey-error', new Error(reason));
      return;
    }

    // A vendor authorisation stands on its own: it proves more than a signature
    // made with the key being replaced ever could, and requiring both would
    // make the one case this exists for — recovering a fleet whose server lost
    // its signing key — impossible again. Without one, the old rules apply.
    if (!vendor && !authorizeCommand(command, { log: 'rekey', audit: 'rekey' })) return;

    const parsed = keys.validatePublicKey(command && command.publicKey);
    if (!parsed.ok) {
      const reason = `refusing rekey: ${parsed.reason}`;
      actions.log('rekey.refused', { reason: parsed.reason });
      logger.error(reason);
      client.send({ type: 'ack', id: command && command.id, accepted: false, reason });
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: reason });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'rekey', ok: false, detail: reason });
      emitter.emit('rekey-error', new Error(reason));
      return;
    }
    client.send({ type: 'ack', id: command && command.id, accepted: true, runtime: capabilities.managed || 'unmanaged' });
    if (pinnedKey && pinnedKey.trim() === parsed.pem.trim()) {
      // Already the key we trust. Still record the authorisation: a re-sent
      // proof with a HIGHER sequence is how the anti-rollback floor rises
      // without the key itself changing.
      if (vendor) recordVendorTrust(vendor);
      actions.log('rekey.unchanged', { fingerprint: parsed.fingerprint });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'rekey', ok: true, detail: `unchanged (${parsed.fingerprint.slice(0, 12)}…)` });
      emitter.emit('rekeyed', { fingerprint: parsed.fingerprint, changed: false });
      return;
    }
    try {
      keys.writePinnedKey(pinnedKeyPath, parsed.pem);
      pinnedKey = parsed.pem;
      // Best-effort: keep the unit's environment in step, so the key a person
      // reads in the unit is the key the agent uses. A failure here is not a
      // failed rekey — the stored file is what the agent reads at startup.
      const unit = keys.syncSystemdDropIn(parsed.pem);
      // Written AFTER the key, so a crash between the two leaves the agent
      // asking for more proof next time, never less.
      if (vendor) recordVendorTrust(vendor);
      actions.log('rekey.applied', {
        fingerprint: parsed.fingerprint,
        vendor: vendor ? { sequence: vendor.sequence, license: vendor.licenseId } : null,
        unit: unit.ok ? unit.path : null,
        unitReason: unit.ok ? null : unit.reason,
      });
      logger.warn(`AGENT_TRUST_ACCEPTED: release anchor replaced (sha256 ${parsed.fingerprint.slice(0, 12)}…)`
        + `${vendor ? `, vendor-authorised seq ${vendor.sequence}` : ' (no vendor authorisation — legacy path)'}`
        + `${unit.ok ? '' : ` — systemd drop-in not updated: ${unit.reason}`}`);
      if (auditId != null) {
        client.send({ type: 'action-result', auditId, action: 'rekey', ok: true, detail: `pinned ${parsed.fingerprint.slice(0, 12)}…` });
      }
      client.send({ type: 'command-result', id: command && command.id, ok: true, fingerprint: parsed.fingerprint });
      emitter.emit('rekeyed', { fingerprint: parsed.fingerprint, changed: true });
    } catch (err) {
      actions.log('rekey.failed', { error: err.message });
      logger.error(`Rekey failed: ${err.message}`);
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: err.message });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'rekey', ok: false, detail: err.message });
      emitter.emit('rekey-error', err);
    }
  }

  // Handles a server "delete" command: remove this agent from the host. The agent
  // securely wipes its token and runs the shipped uninstall.sh (detached) to stop
  // its service and delete its files. It reports 'completed' to the server FIRST
  // (so the server can finalise the audit row + drop the agent record) because
  // afterwards it has neither token nor process. Docker agents decline (the host
  // removes the container).
  async function handleDelete(command) {
    if (!authorizeCommand(command, { log: 'delete', audit: 'delete' })) return;
    const managed = capabilities.managed;
    const auditId = command && command.auditId;
    if (managed === 'docker') {
      client.send({ type: 'ack', id: command && command.id, accepted: false, runtime: 'docker', reason: 'docker-managed' });
      actions.log('delete.declined', { runtime: 'docker' });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'delete', ok: false, detail: 'docker-managed' });
      logger.warn("Ignoring delete command: runtime 'docker' removes itself via the host.");
      emitter.emit('delete-skipped', { reason: 'docker-managed' });
      return;
    }
    client.send({ type: 'ack', id: command && command.id, accepted: true, runtime: managed || 'unmanaged' });
    actions.log('delete.start', {});
    logger.warn('Delete accepted; wiping token and removing this agent from the host.');
    // Stop an exporter WE provisioned before removing ourselves, so the delete
    // doesn't orphan a root daemon exporting sFlow to a dead collector.
    // Best-effort: an exporter failure must never block the delete itself.
    try {
      if (hsflowdManaged || (await managedByThisAgent())) {
        const r = await hsflowd.disable();
        hsflowdManaged = false;
        actions.log('delete.hsflowd-disabled', { state: r && r.state });
        logger.info(`Stopped the agent-managed hsflowd exporter (${(r && r.state) || 'unknown'}).`);
      }
    } catch { /* best-effort */ }
    try {
      deleter.wipeToken();
      actions.log('delete.token-wiped', {});
      // Tell the server we're done BEFORE the detached removal stops us.
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'delete', ok: true });
      emitter.emit('delete-applied');
      deleter.remove(); // detached: sleeps briefly, then stops the service + removes files
    } catch (err) {
      actions.log('delete.failed', { error: err.message });
      logger.error(`Self-delete failed: ${err.message}`);
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'delete', ok: false, detail: err.message });
      emitter.emit('delete-error', err);
    }
  }

  // Handles a server "install-tool" command: install a missing diagnostic tool
  // (e.g. traceroute) from the host's package manager, then report the outcome.
  // The agent only ever installs tools on its OWN allowlist (toolInstaller) — a
  // tool not on the list is refused regardless of what the server asked for, so
  // a compromised server can't push an arbitrary package. Docker hosts decline
  // (the image owns its packages). systemd/unmanaged proceed with whatever
  // privilege the agent already runs with; a genuine "needs root" surfaces as a
  // distinct failure rather than silently doing nothing.
  async function handleInstallTool(command) {
    if (!authorizeCommand(command, { log: 'install-tool', audit: 'install-tool' })) return;
    const managed = capabilities.managed;
    const auditId = command && command.auditId;
    const tool = (command && command.tool) || '';
    if (managed === 'docker') {
      client.send({ type: 'ack', id: command && command.id, accepted: false, runtime: 'docker', reason: 'docker-managed' });
      actions.log('install-tool.declined', { runtime: 'docker', tool });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'install-tool', ok: false, tool, detail: 'docker-managed' });
      logger.warn("Ignoring install-tool command: runtime 'docker' manages its own packages.");
      emitter.emit('install-tool-skipped', { reason: 'docker-managed', tool });
      return;
    }
    client.send({ type: 'ack', id: command && command.id, accepted: true, runtime: managed || 'unmanaged' });
    actions.log('install-tool.start', { tool });
    logger.info(`Install-tool accepted; installing '${tool}'...`);
    try {
      const result = await installer.installTool({ tool });
      if (result.ok) {
        actions.log('install-tool.applied', { tool, package: result.package, manager: result.manager });
        logger.info(`Installed '${tool}' (${result.package} via ${result.manager}).`);
        if (auditId != null) client.send({ type: 'action-result', auditId, action: 'install-tool', ok: true, tool, package: result.package, manager: result.manager });
        emitter.emit('install-tool-applied', result);
      } else {
        actions.log('install-tool.failed', { tool, error: result.detail });
        logger.warn(`Install of '${tool}' failed: ${result.detail}`);
        if (auditId != null) client.send({ type: 'action-result', auditId, action: 'install-tool', ok: false, tool, detail: result.detail });
        emitter.emit('install-tool-error', result);
      }
    } catch (err) {
      actions.log('install-tool.failed', { tool, error: err.message });
      logger.error(`Install of '${tool}' errored: ${err.message}`);
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'install-tool', ok: false, tool, detail: err.message });
      emitter.emit('install-tool-error', err);
    }
  }

  // Runs an active speed test against the server and submits the result. A 401
  // is fatal; other errors are surfaced but non-terminal.
  async function runSpeedtestAndSubmit(command) {
    try {
      const bytes = Number.isInteger(command && command.bytes) && command.bytes > 0 ? command.bytes : undefined;
      const result = await runSpeedtest({ serverUrl: config.serverUrl, token, bytes, fetchImpl: effectiveFetch });
      const response = await api.postSpeedtest(result);
      logger.info(`Speed test: down ${result.downMbps ?? '?'} / up ${result.upMbps ?? '?'} Mbps.`);
      emitter.emit('speedtest-submitted', { result, response });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return false; }
      logger.error(`Speed test failed: ${err.message}`);
      reportError('speedtest', err);
      emitter.emit('command-error', err);
      return false;
    }
  }

  // Read-only evidence collectors (Fase 6). Each returns bounded text from a
  // read-only source the agent already has — /proc counters, the neighbour table,
  // its own live state. No writes, no new SNMP OID scope. Best-effort per item.
  const evidenceCollectors = {
    'agent.state': async () => [
      `connected: ${client && typeof client.isConnected === 'function' ? (client.isConnected() ? 'yes' : 'no') : 'unknown'}`,
      `lastReportAt: ${lastReportAt ? new Date(lastReportAt).toISOString() : 'never'}`,
      `sources: ${(capabilities.sources || []).join(', ') || 'none'}`,
      `monitorSource: ${monitorConfig && monitorConfig.source ? monitorConfig.source : 'unknown'}`,
      `agentVersion: ${capabilities.agentVersion || 'unknown'}`,
    ].join('\n'),
    'iface.counters': async () => fs.readFileSync('/proc/net/dev', 'utf8'),
    'arp.table': async () => fs.readFileSync('/proc/net/arp', 'utf8'),
    'snmp.reads': async () => (monitorConfig && monitorConfig.source === 'snmp'
      ? `SNMP collector target: ${(monitorConfig.snmp && monitorConfig.snmp.host) || 'configured'} (read-only counters already polled by the collector).`
      : 'SNMP not configured on this agent.'),
  };

  // Handles a read-only evidence-snapshot command. Verifies the server signature
  // (when the release key is configured — reusing the release verifier), enforces
  // the agent's OWN read-only allowlist per item, collects, and replies. Never
  // performs a write action; a non-allowlisted item is refused.
  async function handleEvidence(command) {
    // Defense in depth: if the command is signed AND we have the pinned key, it
    // MUST verify or we refuse the whole snapshot (fail closed).
    if (command && command.signature && pinnedKey) {
      const payload = {
        name: command.name, snapshotId: command.snapshotId, clusterId: command.clusterId,
        commandSetVersion: command.commandSetVersion, items: command.items,
      };
      if (!verifyManifest(payload, command.signature, pinnedKey)) {
        actions.log('evidence.refused', { reason: 'bad-signature', snapshotId: command.snapshotId });
        client.send({ type: 'command-result', id: command.id, ok: false, error: 'evidence command signature verification failed' });
        return;
      }
    }
    const collector = createEvidenceCollector({ collectors: evidenceCollectors });
    const items = await collector.collect(command && command.items);
    actions.log('evidence.capture', { snapshotId: command && command.snapshotId, items: items.map((i) => ({ name: i.name, status: i.status })) });
    client.send({
      type: 'command-result', id: command && command.id, ok: true,
      evidence: { commandSetVersion: command && command.commandSetVersion, items },
    });
    emitter.emit('evidence-captured', { snapshotId: command && command.snapshotId, items });
  }

  // The dispatcher below is `async`, and an async listener on an EventEmitter
  // has nowhere to put a rejection: it becomes an unhandled rejection, which on
  // a bare Node process is an exit. One handler that forgets an internal
  // try/catch would therefore take the whole agent down — from a host where
  // nobody is watching, so the only symptom is a gap in the data.
  //
  // dispatchCommand() holds the routing; this wrapper owns the failure. A
  // handler that throws costs its own command an error reply, not the agent.
  client.on('command', (command) => {
    Promise.resolve()
      .then(() => dispatchCommand(command))
      .catch((err) => {
        logger.error(`Command handler failed: ${err && err.message}`);
        // Just enough to name the command in the local trail. Deliberately not
        // command.js's verbOf(): that module's exports are swept by the gate as
        // the recogniser set, and a parser is not a recogniser.
        const verb = (command && typeof command === 'object' && (command.name || command.action || command.type))
          || (typeof command === 'string' ? command : '')
          || 'unknown';
        actions.log('command.failed', { verb: String(verb).slice(0, 48), reason: err && err.message });
        // Tell the server, so the dashboard shows a failed action instead of a
        // request that silently never completed. Best-effort: the socket may be
        // exactly what just broke.
        try {
          client.send({ type: 'command-result', id: command && command.id, ok: false, error: `handler failed: ${err && err.message}` });
          if (command && command.auditId != null) {
            client.send({ type: 'action-result', auditId: command.auditId, ok: false, detail: `handler failed: ${err && err.message}` });
          }
        } catch { /* the channel is gone; the log above is the record */ }
        emitter.emit('command-failed', { command, error: err });
      });
  });

  async function dispatchCommand(command) {
    if (isPingCommand(command)) {
      handlePing(command);
      return;
    }
    if (isEvidenceCommand(command)) {
      await handleEvidence(command);
      return;
    }
    if (isDiagnoseCommand(command)) {
      handleDiagnose(command);
      return;
    }
    if (isUpdateCommand(command)) {
      await handleUpdate(command);
      return;
    }
    if (isRekeyCommand(command)) {
      logger.info('Received rekey command; replacing the release trust anchor.');
      await handleRekey(command);
      return;
    }
    if (isDeleteCommand(command)) {
      await handleDelete(command);
      return;
    }
    if (isInstallToolCommand(command)) {
      logger.info(`Received install-tool command (${command.tool}).`);
      await handleInstallTool(command);
      return;
    }
    if (isSpeedtestCommand(command)) {
      logger.info('Received speed-test command; measuring throughput...');
      await runSpeedtestAndSubmit(command);
      return;
    }
    if (isRunProbeCommand(command)) {
      logger.info(`Received run-probe command (${command.probe.type}).`);
      await runProbeAndSubmit(command.probe);
      return;
    }
    if (isStopBurstCommand(command)) {
      const wasRunning = burst.cancel();
      logger.info(wasRunning ? 'Received stop-burst; stopping at the next tick.' : 'Received stop-burst; nothing running.');
      client.send({ type: 'command-result', id: command && command.id, ok: true, stopped: wasRunning });
      return;
    }
    if (isBurstCommand(command)) {
      logger.info(`Received burst command (${command.target}).`);
      await handleBurst(command);
      return;
    }
    if (isPollSnmpCommand(command)) {
      logger.info('Received poll-snmp command; polling assigned switches now.');
      // Both cycles, because "poll now" from the dashboard means the whole
      // device, not the half of it this command happened to be written for.
      const r = await runSnmpCycle({ force: true });
      const c = await runSnmpCounterCycle({ force: true });
      client.send({ type: 'command-result', id: command && command.id, ok: true, snmp: r, counters: c });
      return;
    }
    if (isRunDiscoveryCommand(command)) {
      logger.info('Received run-discovery command; sweeping configured scope.');
      await runDiscoveryAndSubmit(command.discovery);
      return;
    }
    if (!isRunTestCommand(command)) {
      logger.warn(`Ignoring unrecognised command: ${JSON.stringify(command)}`);
      emitter.emit('command-ignored', command);
      return;
    }
    logger.info('Received run-test command; measuring traffic...');
    await runAndSubmit(command, 'command');
  }

  return {
    agentId,
    start() {
      fatal = false;
      client.start();
      // Bootstrap (capabilities + config) runs async; don't block the caller.
      (async () => {
        await reportCapabilities();
        if (fatal) return;
        await loadServerConfig();
        if (fatal) return;
        startReporting();
        startScheduledProbes();
        await startSyslog();
        await startTraps();
        // The tick only asks which devices are due; the per-device interval
        // decides what is actually polled.
        snmp.start({ tickMs: 30000 });
        // The counter tick is faster than the topology one, because a counter
        // series' interval is its resolution: a five-minute sample cannot show
        // a two-minute error burst at all. It only asks which devices are due.
        snmp.startCounters({ tickMs: 15000 });
        // Start running any persisted transaction tests (server pushes fresh
        // config on connect, which replaces these).
        try { txManager.start(); } catch (err) { logger.warn(`Transaction manager start failed: ${err.message}`); }
      })();
    },
    stop() {
      if (confirmTimer) { clearTimeout(confirmTimer); confirmTimer = null; }
      stopReporting();
      stopScheduledProbes();
      stopSyslog();
      stopTraps();
      burst.cancel();
      snmp.stop();
      txManager.stop();
      if (currentSampler && typeof currentSampler.stop === 'function') currentSampler.stop();
      client.stop();
    },
    // Exposed for tests / manual triggering.
    reportNow: () => runAndSubmit({ name: 'auto-report', intervalMs: config.reportSampleMs }, 'manual'),
    runScheduledProbesNow: () => runScheduledProbes(),
    flushDeviceEventsNow: () => flushDeviceEvents(),
    runSnmpCycleNow: (opts) => runSnmpCycle({ force: true, ...(opts || {}) }),
    runSnmpCounterCycleNow: (opts) => runSnmpCounterCycle({ force: true, ...(opts || {}) }),
    runBurstNow: (spec) => handleBurst(spec),
    getMonitorConfig: () => monitorConfig,
    getHsflowdState: () => lastHsflowdState,
    getDiagnostic: () => buildDiagnostic(),
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
