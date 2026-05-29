'use strict';

const { EventEmitter } = require('events');
const { createAgentClient } = require('./agentClient');
const { createApiClient } = require('./apiClient');
const { isRunTestCommand } = require('./command');
const { runTest } = require('./testRunner');

// Ties the WebSocket client and the REST client together: on a "run test"
// command it runs the test and submits results. A token rejected over REST
// (401) is treated as fatal, mirroring the WebSocket behaviour.
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

    logger.info('Received run-test command; running test...');
    try {
      const result = await runTest(command);
      const response = await api.postResults([result]);
      logger.info('Test complete; results submitted.');
      emitter.emit('results-submitted', { result, response });
    } catch (err) {
      if (err.code === 'TOKEN_REJECTED') {
        logger.error(
          'Token rejected (HTTP 401) when submitting results; stopping. Will NOT re-enroll automatically.'
        );
        client.stop();
        emitter.emit('fatal', 'rest-token-rejected');
        return;
      }
      logger.error(`Failed to run/submit test: ${err.message}`);
      emitter.emit('command-error', err);
    }
  });

  return {
    agentId,
    start() {
      client.start();
    },
    stop() {
      client.stop();
    },
    on: emitter.on.bind(emitter),
    once: emitter.once.bind(emitter),
  };
}

module.exports = { createAgentRuntime };
