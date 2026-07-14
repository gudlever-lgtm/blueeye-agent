#!/usr/bin/env node
'use strict';

const { loadConfig } = require('./config');
const { createLogger } = require('./logger');
const { collectSystemInfo } = require('./system');
const { ensureToken } = require('./bootstrap');
const { createAgentRuntime } = require('./runtime');
const { parseArgs, runEnroll, USAGE } = require('./cli');
const { makePinnedFetch } = require('./httpsClient');
const { resolveEffectiveServerUrl } = require('./serverUrl');
const { closeNetworkHandles } = require('./shutdown');

// Drain lingering network handles, then exit. On Windows a bare process.exit()
// that races libuv's teardown of an undici keep-alive socket (Node's built-in
// fetch) aborts with a native assertion and a non-zero code — which made a
// SUCCESSFUL `enroll` look like a failure to the installer. Closing those handles
// first makes the exit clean everywhere.
async function exit(code) {
  await closeNetworkHandles();
  process.exit(code);
}

// CLI entry point. This is the only place that calls process.exit — all the
// logic lives in injectable modules so it can be tested without spawning a
// process.
async function main() {
  const logger = createLogger({ level: process.env.BLUEEYE_LOG_LEVEL || 'info' });
  const { cmd, opts } = parseArgs(process.argv);

  if (opts.help || cmd === 'help') {
    process.stdout.write(`${USAGE}\n`);
    await exit(0);
    return;
  }

  // `blueeye-agent enroll` exchanges a code for a token and exits — it does not
  // start the long-running runtime.
  if (cmd === 'enroll') {
    const config = loadConfig();
    const systemInfo = collectSystemInfo();
    try {
      await runEnroll({ opts, config, systemInfo, logger });
      await exit(0);
    } catch (err) {
      const detail = err.detail ? ` — ${JSON.stringify(err.detail)}` : '';
      logger.error(`Enrollment failed: ${err.message}${detail}`);
      await exit(1);
    }
    return;
  }

  // `blueeye-agent doctor` — run the connection self-test and exit. Meant to be
  // run right after install (the installer calls it) or by hand on an offline
  // agent: it reports why it can't connect and how to fix it. Read-only.
  if (cmd === 'doctor' || cmd === 'check' || cmd === 'test-connection') {
    const { runDoctor, formatReport } = require('./doctor');
    const config = loadConfig();
    logger.info('Running BlueEye agent connection self-test...');
    const report = await runDoctor({ config });
    process.stdout.write(`${formatReport(report)}\n`);
    await exit(report.connected ? 0 : 1);
    return;
  }

  if (cmd) {
    logger.error(`Unknown command: ${cmd}\n${USAGE}`);
    await exit(1);
    return;
  }

  const config = loadConfig();
  const systemInfo = collectSystemInfo();

  logger.info(
    `BlueEye agent starting on ${systemInfo.hostname} (${systemInfo.platform}/${systemInfo.arch}).`
  );

  // Self-heal an http:// URL against an HTTPS-forcing server: if the server
  // redirects to https on the same host, adopt it now so the WebSocket uses wss://
  // (it won't follow a redirect) and the REST auth header isn't dropped on the
  // http→https hop (which otherwise looks like a fatal 401). No-op for https URLs.
  config.serverUrl = await resolveEffectiveServerUrl({
    serverUrl: config.serverUrl,
    fingerprint: config.serverCertFingerprint,
    logger,
  });
  logger.info(`Server: ${config.serverUrl}`);

  // Pin the server's cert on the enrollment request too (it carries the one-time
  // code and receives the permanent token). Mirrors runtime's REST pinning; falls
  // back to plain fetch for http/dev so existing flows are unchanged.
  const fp = config.serverCertFingerprint;
  const enrollFetch = (fp && /^https:/i.test(config.serverUrl)) ? makePinnedFetch(fp) : fetch;

  let credentials;
  try {
    credentials = await ensureToken({ config, systemInfo, logger, fetchImpl: enrollFetch });
  } catch (err) {
    const detail = err.detail ? ` — ${JSON.stringify(err.detail)}` : '';
    logger.error(`${err.message}${detail}`);
    await exit(1);
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
    exit(1);
  });

  runtime.start();

  function shutdown(signal) {
    logger.info(`Received ${signal}; shutting down.`);
    runtime.stop();
    exit(0);
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
