'use strict';

// An agent asking for its own update.
//
// Updates used to be pure push: an admin clicked, and the click had to land while
// the agent happened to be connected. A host that is online for ten minutes a day
// was therefore effectively un-updatable, and nothing on the agent even knew it
// was behind. Now the server states what it offers in the config the agent
// already reads on every connect, and the agent asks.
//
// Every test here is about a reason NOT to ask, because that is where this can go
// wrong: an agent that asks on every reconnect, or asks to be downgraded, or
// restarts itself in the middle of the afternoon.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { startFakeServer } = require('../test-support/fakeServer');
const { createAgentRuntime } = require('../src/runtime');
const { silentLogger } = require('../src/logger');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message || `timeout after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
const onceEvent = (emitter, name) => new Promise((resolve) => emitter.once(name, resolve));
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const makeConfig = (server, extra = {}) => ({
  serverUrl: server.url,
  heartbeatMs: 10000,
  backoff: { baseMs: 30, maxMs: 120, factor: 2 },
  reportIntervalMs: 0,
  probeIntervalMs: 0,
  capabilitiesIntervalMs: 0,
  configRefreshIntervalMs: 0,
  syslogEnabled: false,
  autoUpdateEnabled: true,
  ...extra,
});

const caps = (over = {}) => ({
  sources: ['proc'], unavailable: {}, agentVersion: '0.9.0', managed: 'systemd', ...over,
});

async function startedRuntime(server, { config = {}, capabilities = {} } = {}) {
  const runtime = createAgentRuntime({
    config: makeConfig(server, config),
    token: 'valid',
    agentId: 1,
    logger: silentLogger,
    capabilities: caps(capabilities),
    collectLldp: async () => ({ unavailable: 'test' }),
  });
  const connected = onceEvent(runtime, 'connected');
  runtime.start();
  await withTimeout(connected, 4000, 'never connected');
  return runtime;
}

const requestFrame = (server) => server.waitForWsMessage((m) => m.type === 'update-request');

test('an agent that is behind asks for the update, once per offered version', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    updates: { agentVersion: '1.0.0', auto: true, window: '' },
  });
  const runtime = await startedRuntime(server);
  try {
    const frame = await withTimeout(requestFrame(server), 4000, 'never asked');
    assert.equal(frame.currentVersion, '0.9.0');
    assert.equal(frame.offeredVersion, '1.0.0');

    // A second config read for the SAME offered version asks nothing: a
    // reconnect loop must not become an update loop.
    const before = server.receivedWsMessages.filter((m) => m.type === 'update-request').length;
    await runtime.refreshConfigNow();
    await delay(50);
    const after = server.receivedWsMessages.filter((m) => m.type === 'update-request').length;
    assert.equal(after, before, 'asked once, not once per config read');

    // A NEWER offer is a new question.
    server.setUpdateOffer({ agentVersion: '1.1.0', auto: true, window: '' });
    const second = server.waitForWsMessage((m) => m.type === 'update-request' && m.offeredVersion === '1.1.0');
    await runtime.refreshConfigNow();
    assert.equal((await withTimeout(second, 4000, 'never asked again')).offeredVersion, '1.1.0');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('nothing is asked when the server has not enabled auto-update', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    updates: { agentVersion: '1.0.0', auto: false, window: '' },
  });
  const runtime = await startedRuntime(server);
  try {
    await delay(150);
    assert.equal(server.receivedWsMessages.some((m) => m.type === 'update-request'), false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('the local opt-out wins over the server policy', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    updates: { agentVersion: '1.0.0', auto: true, window: '' },
  });
  const runtime = await startedRuntime(server, { config: { autoUpdateEnabled: false } });
  try {
    await delay(150);
    assert.equal(server.receivedWsMessages.some((m) => m.type === 'update-request'), false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an older or equal offer is never asked for — a downgrade is not an update', async () => {
  for (const offered of ['0.9.0', '0.8.0']) {
    const server = await startFakeServer({
      validTokens: ['valid'],
      updates: { agentVersion: offered, auto: true, window: '' },
    });
    const runtime = await startedRuntime(server);
    try {
      await delay(150);
      assert.equal(
        server.receivedWsMessages.some((m) => m.type === 'update-request'),
        false,
        `v${offered} must not be asked for by an agent on 0.9.0`
      );
    } finally {
      runtime.stop();
      await server.close();
    }
  }
});

test('a runtime nothing can restart does not ask', async () => {
  for (const managed of ['docker', 'unmanaged']) {
    const server = await startFakeServer({
      validTokens: ['valid'],
      updates: { agentVersion: '1.0.0', auto: true, window: '' },
    });
    const runtime = await startedRuntime(server, { capabilities: { managed } });
    try {
      await delay(150);
      assert.equal(server.receivedWsMessages.some((m) => m.type === 'update-request'), false, `${managed} must not ask`);
    } finally {
      runtime.stop();
      await server.close();
    }
  }
});

test('a Windows service and a launchd job DO ask', async () => {
  for (const managed of ['windows-service', 'launchd']) {
    const server = await startFakeServer({
      validTokens: ['valid'],
      updates: { agentVersion: '1.0.0', auto: true, window: '' },
    });
    const runtime = await startedRuntime(server, { capabilities: { managed } });
    try {
      const frame = await withTimeout(requestFrame(server), 4000, `${managed} never asked`);
      assert.equal(frame.offeredVersion, '1.0.0');
    } finally {
      runtime.stop();
      await server.close();
    }
  }
});

test('outside the maintenance window the agent waits', async () => {
  // A window that certainly does not contain "now": the minute we are in, plus
  // one, for one minute. A monitoring agent restarting mid-incident is its own
  // kind of outage, so this is the case that must hold.
  const now = new Date();
  const start = new Date(now.getTime() + 120000);
  const end = new Date(now.getTime() + 180000);
  const pad = (n) => String(n).padStart(2, '0');
  const window = `${pad(start.getHours())}:${pad(start.getMinutes())}-${pad(end.getHours())}:${pad(end.getMinutes())}`;

  const server = await startFakeServer({
    validTokens: ['valid'],
    updates: { agentVersion: '1.0.0', auto: true, window },
  });
  const runtime = await startedRuntime(server);
  try {
    await delay(150);
    assert.equal(server.receivedWsMessages.some((m) => m.type === 'update-request'), false);
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('an offer inside the window is asked for', async () => {
  const server = await startFakeServer({
    validTokens: ['valid'],
    updates: { agentVersion: '1.0.0', auto: true, window: '00:00-23:59' },
  });
  const runtime = await startedRuntime(server);
  try {
    const frame = await withTimeout(requestFrame(server), 4000, 'never asked');
    assert.equal(frame.offeredVersion, '1.0.0');
  } finally {
    runtime.stop();
    await server.close();
  }
});

test('a server that offers nothing is not a problem', async () => {
  const server = await startFakeServer({ validTokens: ['valid'] });
  const runtime = await startedRuntime(server);
  try {
    await delay(150);
    assert.equal(server.receivedWsMessages.some((m) => m.type === 'update-request'), false);
  } finally {
    runtime.stop();
    await server.close();
  }
});
