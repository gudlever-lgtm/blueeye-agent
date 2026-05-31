'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand } = require('./command');
const { runTest } = require('./testRunner');

// Ties the WebSocket client and the REST client together:
//   - on a server "run test" command it measures + submits once;
//   - independently, it reports traffic on a fixed interval (continuous
//     reporting) so the server gets data without anyone triggering it.
// A token rejected over REST (401) is treated as fatal, mirroring the WS path.
//
// Events: 'open', 'connected', 'close', 'results-submitted', 'command-ignored',
// 'command-error', 'fatal'. It never calls process.exit — that is the CLI's job.
function createAgentRuntime({ config, token, agentId, logger, fetchImpl = fetch, WebSocketImpl }) {
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

  // Measures traffic and submits the result. `source` is just for logging
  // ('command' vs 'auto'). A 401 stops everything (fatal); other errors are
  // surfaced but non-terminal so the periodic loop keeps running.
  async function runAndSubmit(command, source) {
    try {
      const result = await runTest(command);
      const response = await api.postResults([result]);
      logger.info(`Traffic measured (${source}); results submitted.`);
      emitter.emit('results-submitted', { result, response, source });
      return true;
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') {
        fatal = true;
        stopReporting();
        logger.error(
          'Token rejected (HTTP 401) when submitting results; stopping. Will NOT re-enroll automatically.'
        );
        client.stop();
        emitter.emit('fatal', 'rest-token-rejected');
        return false;
      }
      logger.error(`Failed to measure/submit traffic (${source}): ${err.message}`);
      emitter.emit('command-error', err);
      return false;
    }
  }

  function startReporting() {
    const interval = config.reportIntervalMs;
    if (!interval || interval <= 0) {
      logger.info('Continuous reporting disabled (reportIntervalMs <= 0).');
      return;
    }
    stopReporting();
    const command = { name: 'auto-report', intervalMs: config.reportSampleMs };
    logger.info(`Continuous reporting every ${interval}ms (sample ${config.reportSampleMs}ms).`);
    // Report once shortly after start, then on the interval. Overlapping runs
    // are avoided because each tick awaits before the next is scheduled.
    let running = false;
    reportTimer = setInterval(async () => {
      if (fatal || running) return;
      running = true;
      try {
        await runAndSubmit(command, 'auto');
      } finally {
        running = false;
      }
    }, interval);
    if (reportTimer.unref) reportTimer.unref();
  }

  function stopReporting() {
    if (reportTimer) {
      clearInterval(reportTimer);
      reportTimer = null;
    }
  }

  client.on('open', () => emitter.emit('open'));
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
      startReporting();
    },
    stop() {
      stopReporting();
      client.stop();
    },
    // Exposed for tests / manual triggering.
    reportNow: () => runAndSubmit({ name: 'auto-report', intervalMs: config.reportSampleMs }, 'manual'),
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
