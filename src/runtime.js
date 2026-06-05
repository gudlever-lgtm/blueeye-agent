'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand, isRunProbeCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand } = require('./command');
const { createSelfUpdater } = require('./selfUpdate');
const { runSpeedtest } = require('./speedtest');
const { runTest } = require('./testRunner');
const { runProbe } = require('./probes');
const { resolveProbeTargets } = require('./probes/targets');
const { createSampler } = require('./monitor');
const { detectCapabilities } = require('./capabilities');
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
  selfUpdater = null,
}) {
  const emitter = new EventEmitter();
  const updater = selfUpdater || createSelfUpdater({ logger });
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

  function handleFatal(reason = 'rest-token-rejected') {
    if (fatal) return;
    fatal = true;
    stopReporting();
    logger.error('Token rejected (HTTP 401); stopping. Will NOT re-enroll automatically.');
    client.stop();
    emitter.emit('fatal', reason);
  }

  // Measures traffic (with the currently selected sampler) and submits it. A 401
  // is fatal; other errors are surfaced but non-terminal so the loop continues.
  async function runAndSubmit(command, source) {
    try {
      const result = await runTest(command, { sampler: currentSampler });
      const response = await api.postResults([result]);
      logger.info(`Traffic measured (${source}, ${monitorConfig.source}); results submitted.`);
      emitter.emit('results-submitted', { result, response, source });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') {
        handleFatal();
        return false;
      }
      logger.error(`Failed to measure/submit traffic (${source}): ${err.message}`);
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
      emitter.emit('command-error', err);
      return false;
    }
  }

  // Reports capabilities to the server. Resilient: only a 401 is fatal.
  async function reportCapabilities() {
    try {
      await api.postCapabilities(capabilities);
      logger.info(`Reported capabilities: ${capabilities.sources.join(', ') || '(none)'}`);
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return; }
      logger.warn(`Could not report capabilities (${err.message}).`);
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
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') { handleFatal(); return; }
      logger.warn(`Could not fetch monitor config (${err.message}); using ${monitorConfig.source}.`);
    }
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
    // On (re)connect, refresh config so source changes are picked up.
    if (!fatal) loadServerConfig().catch(() => {});
  });
  client.on('connected', (m) => emitter.emit('connected', m));
  client.on('close', (code) => emitter.emit('close', code));
  // A WS-origin fatal (e.g. 401 handshake) must fully shut the runtime down too
  // — stop reporting + mark fatal — not just re-emit, so no timers linger.
  client.on('fatal', (reason) => handleFatal(reason));

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
    if (managed !== 'systemd') {
      const reason = managed === 'docker' ? 'docker-managed' : 'unmanaged';
      client.send({ type: 'ack', id: command && command.id, accepted: false, runtime: managed || 'unmanaged', reason });
      logger.warn(`Ignoring update command: runtime '${managed}' is not self-updatable (systemd only).`);
      emitter.emit('update-skipped', { managed, reason });
      return;
    }
    client.send({ type: 'ack', id: command && command.id, accepted: true, runtime: 'systemd' });
    logger.info('Update accepted; downloading and rebuilding from the server source...');
    try {
      await updater.update({
        serverUrl: config.serverUrl,
        token,
        expectedSha: command && command.sha256,
        fetchImpl: effectiveFetch,
      });
      logger.info('Update applied; requesting service restart.');
      emitter.emit('update-applied');
      updater.restart(); // systemd stops us (SIGTERM -> graceful exit) then starts the new code
    } catch (err) {
      logger.error(`Self-update failed: ${err.message}`);
      client.send({ type: 'command-result', id: command && command.id, ok: false, error: err.message });
      emitter.emit('update-error', err);
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
      emitter.emit('command-error', err);
      return false;
    }
  }

  client.on('command', async (command) => {
    if (isPingCommand(command)) {
      handlePing(command);
      return;
    }
    if (isUpdateCommand(command)) {
      await handleUpdate(command);
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
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
