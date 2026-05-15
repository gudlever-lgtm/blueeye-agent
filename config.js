import os from 'node:os';

const SERVER_URL = process.env.SERVER_URL;

if (!SERVER_URL) {
  throw new Error('[agent] SERVER_URL er ikke sat — agenten kan ikke starte');
}

export const config = {
  serverUrl: SERVER_URL,
  agentId: process.env.AGENT_ID || os.hostname(),
  reconnectIntervalMs: Number(process.env.RECONNECT_INTERVAL_MS) || 5000,
  testTimeoutMs: Number(process.env.TEST_TIMEOUT_MS) || 30000,
};
