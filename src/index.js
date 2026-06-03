#!/usr/bin/env node
'use strict';

const { loadConfig } = require('./config');
const { createLogger } = require('./logger');
const { collectSystemInfo } = require('./system');
const { ensureToken } = require('./bootstrap');
const { createAgentRuntime } = require('./runtime');
const { parseArgs, runEnroll, USAGE } = require('./cli');

// CLI entry point. This is the only place that calls process.exit — all the
// logic lives in injectable modules so it can be tested without spawning a
// process.
async function main() {
  const logger = createLogger({ level: process.env.BLUEEYE_LOG_LEVEL || 'info' });
  const { cmd, opts } = parseArgs(process.argv);

  if (opts.help || cmd === 'help') {
    process.stdout.write(`${USAGE}\n`);
    process.exit(0);
    return;
  }

  // `blueeye-agent enroll` exchanges a code for a token and exits — it does not
  // start the long-running runtime.
  if (cmd === 'enroll') {
    const config = loadConfig();
    const systemInfo = collectSystemInfo();
    try {
      await runEnroll({ opts, config, systemInfo, logger });
      process.exit(0);
    } catch (err) {
      const detail = err.detail ? ` — ${JSON.stringify(err.detail)}` : '';
      logger.error(`Enrollment failed: ${err.message}${detail}`);
      process.exit(1);
    }
    return;
  }

  if (cmd) {
    logger.error(`Unknown command: ${cmd}\n${USAGE}`);
    process.exit(1);
    return;
  }

  const config = loadConfig();
  const systemInfo = collectSystemInfo();

  logger.info(
    `BlueEye agent starting on ${systemInfo.hostname} (${systemInfo.platform}/${systemInfo.arch}).`
  );
  logger.info(`Server: ${config.serverUrl}`);

  let credentials;
  try {
    credentials = await ensureToken({ config, systemInfo, logger });
  } catch (err) {
    const detail = err.detail ? ` — ${JSON.stringify(err.detail)}` : '';
    logger.error(`${err.message}${detail}`);
    process.exit(1);
    return;
  }

  const runtime = createAgentRuntime({
    config,
    token: credentials.token,
    agentId: credentials.agentId,
    logger,
  });

  // A fatal state (token rejected over WS or REST) is terminal: exit and let the
  // operator decide. The agent never re-enrolls on its own.
  runtime.on('fatal', () => {
    logger.error('Agent is in a fatal state; exiting. Manual re-enrollment is required.');
    process.exit(1);
  });

  runtime.start();

  function shutdown(signal) {
    logger.info(`Received ${signal}; shutting down.`);
    runtime.stop();
    process.exit(0);
  }
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`Fatal: ${err.stack || err.message}`);
    process.exit(1);
  });
}

module.exports = { main };
