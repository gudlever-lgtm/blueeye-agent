'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand, isRunProbeCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand, isDiagnoseCommand, isDeleteCommand, isInstallToolCommand } = require('./command');
const { createSelfUpdater } = require('./selfUpdate');
const { createSelfDeleter } = require('./selfDelete');
const { createToolInstaller } = require('./toolInstaller');
const { createActionLog } = require('./actionLog');
const { resolveReleasePublicKey } = require('./release/publicKey');
const { runSpeedtest } = require('./speedtest');
const { runTest } = require('./testRunner');
const { runProbe } = require('./probes');
const { resolveProbeTargets } = require('./probes/targets');
const { createSampler } = require('./monitor');
const { createHsflowdManager } = require('./sflow/hsflowd');
const { detectCapabilities } = require('./capabilities');
const { collectNicInfo } = require('./nicInfo');
const { makePinnedFetch } = require('./httpsClient');

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
  selfUpdater = null,
  selfDeleter = null,
  toolInstaller = null,
  actionLog = null,
  hsflowdManager = null,
}) {
  const emitter = new EventEmitter();
  const updater = selfUpdater || createSelfUpdater({ logger });
  // The deleter must wipe the token the runtime actually uses: tokenPath can be
  // set via the config FILE (not just env), and selfDelete's own default only
  // sees the env — so a file-configured path would be left un-wiped.
  const deleter = selfDeleter || createSelfDeleter({ logger, tokenPath: config.tokenPath });
  const installer = toolInstaller || createToolInstaller({ logger });
  // Local, server-independent action trail. Path comes from the env at
  // provisioning (BLUEEYE_ACTION_LOG); a no-op when unset. Never logs secrets.
  const actions = actionLog || createActionLog({ path: process.env.BLUEEYE_ACTION_LOG || '' });
  // The agent's release trust anchor — used to verify a signed update before it
  // touches disk. Resolved once at startup.
  const releasePublicKey = resolveReleasePublicKey();
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

  let reportTimer = null;
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
  async function runProbeAndSubmit(probeSpec) {
    try {
      const result = await probeRunner(probeSpec);
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

  // Reports capabilities to the server. Resilient: only a 401 is fatal. NIC
  // inventory (driver/firmware per interface) is collected best-effort and
  // folded in, so the server can spot fleet-wide firmware drift; a failure to
  // read it just omits the field.
  async function reportCapabilities() {
    let payload = capabilities;
    try {
      const nic = await collectNic();
      if (Array.isArray(nic) && nic.length) payload = { ...capabilities, nic };
    } catch { /* NIC inventory is best-effort */ }
    try {
      await api.postCapabilities(payload);
      const nicNote = payload.nic ? ` + ${payload.nic.length} NIC(s)` : '';
      logger.info(`Reported capabilities: ${capabilities.sources.join(', ') || '(none)'}${nicNote}`);
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
      const mc = await api.getConfig();
      monitorConfig = mc;
      // Dispose the previous sampler's background lifecycle (e.g. a netflow
      // UDP socket) before swapping in the new source.
      if (currentSampler && typeof currentSampler.stop === 'function') currentSampler.stop();
      currentSampler = samplerFactory(monitorConfig, { logger });
      effectiveIntervalMs =
        Number.isInteger(mc.intervalMs) && mc.intervalMs > 0 ? mc.intervalMs : config.reportIntervalMs;
      logger.info(`Monitor source: ${monitorConfig.source} (report every ${effectiveIntervalMs}ms).`);
      emitter.emit('config', monitorConfig);
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
    }
  });
  client.on('connected', (m) => emitter.emit('connected', m));
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

  // Handles a server "update" command: acknowledge immediately (so the dashboard
  // learns whether we can self-update), then — only when systemd-managed —
  // rebuild from the server's verified source bundle and restart. Docker and
  // unmanaged agents decline; their host rebuilds them.
  async function handleUpdate(command) {
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
        publicKey: releasePublicKey,
        fetchImpl: effectiveFetch,
      });
      actions.log('update.applied', { version: targetVersion });
      logger.info('Update applied; requesting service restart.');
      // Report completion BEFORE restarting — once systemd swaps us we can't speak.
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: true, version: targetVersion });
      emitter.emit('update-applied');
      updater.restart(); // systemd stops us (SIGTERM -> graceful exit) then starts the new code
    } catch (err) {
      actions.log('update.failed', { version: targetVersion, error: err.message });
      logger.error(`Self-update failed: ${err.message}`);
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: err.message });
      if (auditId != null) client.send({ type: 'action-result', auditId, action: 'upgrade', ok: false, detail: err.message });
      emitter.emit('update-error', err);
    }
  }

  // Handles a server "delete" command: remove this agent from the host. The agent
  // securely wipes its token and runs the shipped uninstall.sh (detached) to stop
  // its service and delete its files. It reports 'completed' to the server FIRST
  // (so the server can finalise the audit row + drop the agent record) because
  // afterwards it has neither token nor process. Docker agents decline (the host
  // removes the container).
  async function handleDelete(command) {
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

  client.on('command', async (command) => {
    if (isPingCommand(command)) {
      handlePing(command);
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
    if (!isRunTestCommand(command)) {
      logger.warn(`Ignoring unrecognised command: ${JSON.stringify(command)}`);
      emitter.emit('command-ignored', command);
      return;
    }
    logger.info('Received run-test command; measuring traffic...');
    await runAndSubmit(command, 'command');
  });

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
      })();
    },
    stop() {
      stopReporting();
      stopScheduledProbes();
      if (currentSampler && typeof currentSampler.stop === 'function') currentSampler.stop();
      client.stop();
    },
    // Exposed for tests / manual triggering.
    reportNow: () => runAndSubmit({ name: 'auto-report', intervalMs: config.reportSampleMs }, 'manual'),
    runScheduledProbesNow: () => runScheduledProbes(),
    getMonitorConfig: () => monitorConfig,
    getHsflowdState: () => lastHsflowdState,
    getDiagnostic: () => buildDiagnostic(),
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
