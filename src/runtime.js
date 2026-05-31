'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand } = require('./command');
const { runTest } = require('./testRunner');
const { createSampler } = require('./monitor');
const { detectCapabilities } = require('./capabilities');

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
}) {
  const emitter = new EventEmitter();
  const api = createApiClient({ serverUrl: config.serverUrl, token, fetchImpl });
  const client = createAgentClient({
    serverUrl: config.serverUrl,
    token,
    logger,
    heartbeatMs: config.heartbeatMs,
    backoff: config.backoff,
    WebSocketImpl,
  });

  let reportTimer = null;
  let fatal = false;
  let monitorConfig = { source: 'proc' };
  let currentSampler = samplerFactory(monitorConfig);
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

  // Reports capabilities to the server. Resilient: only a 401 is fatal.
  async function reportCapabilities() {
    try {
      await api.postCapabilities(capabilities);
      logger.info(`Reported capabilities: ${capabilities.sources.join(', ') || '(none)'}`);
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') return handleFatal();
      logger.warn(`Could not report capabilities (${err.message}).`);
    }
  }

  // Fetches the server-assigned monitor config and rebuilds the sampler.
  // Resilient: only a 401 is fatal; otherwise keep the current source.
  async function loadServerConfig() {
    try {
      const mc = (await api.getConfig()) || { source: 'proc' };
      monitorConfig = mc;
      currentSampler = samplerFactory(monitorConfig);
      effectiveIntervalMs =
        Number.isInteger(mc.intervalMs) && mc.intervalMs > 0 ? mc.intervalMs : config.reportIntervalMs;
      logger.info(`Monitor source: ${monitorConfig.source} (report every ${effectiveIntervalMs}ms).`);
      emitter.emit('config', monitorConfig);
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') return handleFatal();
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

  client.on('open', () => {
    emitter.emit('open');
    // On (re)connect, refresh config so source changes are picked up.
    if (!fatal) loadServerConfig().catch(() => {});
  });
  client.on('connected', (m) => emitter.emit('connected', m));
  client.on('close', (code) => emitter.emit('close', code));
  client.on('fatal', (reason) => emitter.emit('fatal', reason));

  client.on('command', async (command) => {
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
      })();
    },
    stop() {
      stopReporting();
      client.stop();
    },
    // Exposed for tests / manual triggering.
    reportNow: () => runAndSubmit({ name: 'auto-report', intervalMs: config.reportSampleMs }, 'manual'),
    getMonitorConfig: () => monitorConfig,
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
