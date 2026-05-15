import test from 'node:test';
import assert from 'node:assert/strict';

import { parsePing } from './latency.js';
import { runCommand } from './exec.js';

// runner.js -> config.js kræver SERVER_URL ved import — sæt den før
// dynamisk import (statiske imports hoistes over almindelige statements).
process.env.SERVER_URL ||= 'ws://localhost:4000';
const { runTest } = await import('../runner.js');

const LINUX_PING = `PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.1 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=18.4 ms

--- 8.8.8.8 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 9012ms
rtt min/avg/max/mdev = 12.123/14.200/18.400/1.100 ms`;

test('parsePing returnerer korrekt JSON-struktur', () => {
  const result = parsePing(LINUX_PING);
  assert.deepEqual(result, {
    avgMs: 14.2,
    minMs: 12.123,
    maxMs: 18.4,
    stddevMs: 1.1,
    packets: 10,
  });
});

test('parsePing kaster ved uparsbart output', () => {
  assert.throws(() => parsePing('no summary here'));
});

test('runTest wrapper indeholder alle test_result-felter', async () => {
  const result = await runTest(
    { testId: 'abc', type: 'unknown-type', target: '8.8.8.8' },
    { timeoutMs: 1000 }
  );
  assert.equal(result.action, 'test_result');
  assert.equal(result.testId, 'abc');
  assert.equal(result.type, 'unknown-type');
  assert.equal(result.target, '8.8.8.8');
  assert.equal(result.status, 'error');
  assert.equal(typeof result.durationMs, 'number');
});

test('runCommand afbrydes når signal aborter undervejs', async () => {
  // "sleep 30" afslutter aldrig inden for testens levetid — svarer
  // til en spawn der aldrig afslutter. Signalet aborter den.
  const controller = new AbortController();
  setTimeout(() => {
    controller.abort(new Error('Command timed out after 30s'));
  }, 50);
  await assert.rejects(
    runCommand('sleep', ['30'], { signal: controller.signal }),
    /timed out/
  );
});

test('runCommand afviser når signal allerede er aborted', async () => {
  const controller = new AbortController();
  controller.abort(new Error('Command timed out after 30s'));
  await assert.rejects(
    runCommand('sleep', ['30'], { signal: controller.signal }),
    /timed out/
  );
});
