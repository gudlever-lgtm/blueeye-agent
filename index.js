import os from 'node:os';
import { WebSocket } from 'ws';
import { config } from './config.js';
import { runTest } from './runner.js';

const PING_INTERVAL_MS = 30000;

function registerMessage() {
  return {
    action: 'register',
    agentId: config.agentId,
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,
  };
}

function connect() {
  console.log(`[ws] Connecting to ${config.serverUrl}`);
  const ws = new WebSocket(config.serverUrl);

  let keepAlive = null;

  ws.on('open', () => {
    console.log(`[ws] Connected to ${config.serverUrl}`);
    ws.send(JSON.stringify(registerMessage()));
    console.log(`[agent] Registered as ${config.agentId}`);

    keepAlive = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      }
    }, PING_INTERVAL_MS);
  });

  ws.on('message', async (data) => {
    let command;
    try {
      command = JSON.parse(data.toString());
    } catch {
      console.warn('[ws] Received invalid JSON, ignoring');
      return;
    }

    if (command.action !== 'run_test') {
      return;
    }

    const result = await runTest(command);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(result));
    }
  });

  ws.on('close', () => {
    if (keepAlive) clearInterval(keepAlive);
    console.warn(
      `[ws] Disconnected — reconnecting in ${config.reconnectIntervalMs}ms`
    );
    setTimeout(connect, config.reconnectIntervalMs);
  });

  ws.on('error', (err) => {
    console.warn(`[ws] Connection error: ${err.message}`);
  });
}

console.log(`[agent] BlueEye Agent starting (id: ${config.agentId})`);
connect();
