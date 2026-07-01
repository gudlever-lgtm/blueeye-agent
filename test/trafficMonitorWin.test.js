'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('events');
const { PassThrough } = require('stream');

const { createWinTrafficSampler, buildScript, parseLine } = require('../src/trafficMonitorWin');

function makeFakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kill = () => {
    if (child.killed) return;
    child.killed = true;
    child.emit('exit', null);
  };
  return child;
}

function counters({ rxBytes = 0, txBytes = 0, rxPackets = 0, txPackets = 0, rxErrors = 0, txErrors = 0, rxDrop = 0, txDrop = 0, operStatus = 'Up', speedMbps = 1000 } = {}) {
  return { rxBytes, txBytes, rxPackets, txPackets, rxErrors, txErrors, rxDrop, txDrop, operStatus, speedMbps };
}

test('buildScript embeds Get-NetAdapterStatistics/Get-NetAdapter and the tick interval', () => {
  const script = buildScript(1234);
  assert.match(script, /Get-NetAdapterStatistics/);
  assert.match(script, /Get-NetAdapter\b/);
  assert.match(script, /ConvertTo-Json/);
  assert.match(script, /Start-Sleep -Milliseconds 1234/);
});

test('parseLine accepts a well-formed tick and rejects corrupt/half-written lines', () => {
  const good = parseLine(JSON.stringify({ ts: 1000, ifaces: { eth0: counters() } }));
  assert.equal(good.ts, 1000);
  assert.ok(good.ifaces.eth0);

  assert.equal(parseLine(''), null);
  assert.equal(parseLine('   '), null);
  assert.equal(parseLine('{"ts": 1000, "ifaces": {"eth0": {"rxBy'), null); // truncated mid-write
  assert.equal(parseLine('{"ts": "not-a-number", "ifaces": {}}'), null);
  assert.equal(parseLine('{"ifaces": {}}'), null); // missing ts
  assert.equal(parseLine('{"ts": 1000}'), null); // missing ifaces
  assert.equal(parseLine('null'), null);
});

test('spawns the powershell process exactly once at creation, not per sample() call', async () => {
  const children = [];
  const spawnFn = () => { const c = makeFakeChild(); children.push(c); return c; };
  const sampler = createWinTrafficSampler({ spawnFn, now: () => 1000, waitMs: async () => {} });
  assert.equal(children.length, 1);

  sampler._feed(JSON.stringify({ ts: 1000, ifaces: { eth0: counters({ rxBytes: 100, txBytes: 200 }) } }));
  await sampler({ intervalMs: 0 });
  await sampler({ intervalMs: 0 });
  assert.equal(children.length, 1, 'no extra powershell.exe spawned per poll');
  sampler.stop();
});

test('sample() computes the same delta/rate shape as the Linux sampler from two fed ticks', async () => {
  const spawnFn = () => makeFakeChild();
  const clock = { t: 1000 };
  let fedSecond = false;
  let sampler;
  const waitMs = async (ms) => {
    clock.t += ms;
    if (!fedSecond) {
      fedSecond = true;
      sampler._feed(JSON.stringify({
        ts: clock.t + 500,
        ifaces: {
          eth0: counters({ rxBytes: 3000, txBytes: 6000, rxPackets: 20, txPackets: 24, operStatus: 'Up', speedMbps: 1000 }),
        },
      }));
    }
  };

  sampler = createWinTrafficSampler({ spawnFn, now: () => clock.t, waitMs });
  sampler._feed(JSON.stringify({
    ts: 1000,
    ifaces: { eth0: counters({ rxBytes: 1000, txBytes: 2000, rxPackets: 10, txPackets: 12 }) },
  }));

  const snap = await sampler({ intervalMs: 500 });
  assert.equal(snap.interfaces.length, 1);
  const eth0 = snap.interfaces[0];
  assert.equal(eth0.iface, 'eth0');
  assert.equal(eth0.rxBytes, 2000); // 3000 - 1000
  assert.equal(eth0.txBytes, 4000); // 6000 - 2000
  assert.equal(eth0.rxPackets, 10);
  assert.equal(eth0.txPackets, 12);
  assert.equal(eth0.operStatus, 'Up');
  assert.equal(eth0.speedMbps, 1000);
  assert.equal(snap.totals.rxBytes, 2000);
  assert.equal(snap.totals.txBytes, 4000);
  sampler.stop();
});

test('sample() ignores corrupt lines interleaved with valid ticks instead of crashing', async () => {
  const spawnFn = () => makeFakeChild();
  const clock = { t: 1000 };
  let fedSecond = false;
  let sampler;
  const waitMs = async (ms) => {
    clock.t += ms;
    if (!fedSecond) {
      fedSecond = true;
      sampler._feed('{"ts": broken json...');
      sampler._feed(JSON.stringify({ ts: clock.t + 100, ifaces: { eth0: counters({ rxBytes: 500, txBytes: 900 }) } }));
    }
  };
  sampler = createWinTrafficSampler({ spawnFn, now: () => clock.t, waitMs });
  sampler._feed(JSON.stringify({ ts: 1000, ifaces: { eth0: counters({ rxBytes: 100, txBytes: 200 }) } }));

  const snap = await sampler({ intervalMs: 100 });
  assert.equal(snap.interfaces[0].rxBytes, 400);
  sampler.stop();
});

test('sample() degrades to an empty-but-valid snapshot if no tick ever arrives', async () => {
  const spawnFn = () => makeFakeChild();
  let elapsed = 0;
  const sampler = createWinTrafficSampler({
    spawnFn,
    now: () => elapsed,
    waitMs: async (ms) => { elapsed += ms; },
    graceMs: 100,
    tickMs: 10,
  });

  const snap = await sampler({ intervalMs: 50 });
  assert.deepEqual(snap.interfaces, []);
  assert.equal(snap.totals.rxBytes, 0);
  sampler.stop();
});

test('respawns the powershell process with backoff after it exits, and stops respawning after stop()', async () => {
  const children = [];
  const spawnFn = () => { const c = makeFakeChild(); children.push(c); return c; };
  const sampler = createWinTrafficSampler({ spawnFn, respawnBaseMs: 5, respawnMaxMs: 20 });
  assert.equal(children.length, 1);

  children[0].emit('exit', 1);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(children.length, 2, 'a fresh process is spawned after the old one exits');

  sampler.stop();
  const countAfterStop = children.length;
  children[1].emit('exit', 1);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(children.length, countAfterStop, 'no respawn after stop()');
});

test('stop() kills the running child process', () => {
  const children = [];
  const spawnFn = () => { const c = makeFakeChild(); children.push(c); return c; };
  const sampler = createWinTrafficSampler({ spawnFn });
  sampler.stop();
  assert.equal(children[0].killed, true);
});
