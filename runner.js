import { performance } from 'node:perf_hooks';
import { config } from './config.js';

import * as latency from './tests/latency.js';
import * as loss from './tests/loss.js';
import * as jitter from './tests/jitter.js';
import * as http from './tests/http.js';
import * as traceroute from './tests/traceroute.js';
import * as dns from './tests/dns.js';
import * as bandwidth from './tests/bandwidth.js';

const REGISTRY = {
  latency,
  loss,
  jitter,
  http,
  traceroute,
  dns,
  bandwidth,
};

// Kører én test-kommando og returnerer altid et test_result-objekt.
// Kaster aldrig — alle fejl fanges og rapporteres som status "error".
export async function runTest(command, { timeoutMs = config.testTimeoutMs } = {}) {
  const { testId, type, target, options = {} } = command;
  const start = performance.now();

  const base = { action: 'test_result', testId, type, target };
  const controller = new AbortController();
  const seconds = Math.round(timeoutMs / 1000);
  const timer = setTimeout(() => {
    controller.abort(new Error(`Command timed out after ${seconds}s`));
  }, timeoutMs);

  try {
    const mod = REGISTRY[type];
    if (!mod) {
      throw new Error(`Unknown test type: ${type}`);
    }

    console.log(`[test] start ${type} -> ${target}`);
    const result = await mod.run(target, options, controller.signal);
    const durationMs = Math.round(performance.now() - start);
    console.log(`[test] done ${type} -> ${target} (${durationMs}ms)`);

    return { ...base, status: 'success', result, durationMs };
  } catch (err) {
    const durationMs = Math.round(performance.now() - start);
    console.warn(`[test] error ${type} -> ${target}: ${err.message}`);

    const out = {
      ...base,
      status: 'error',
      error: err.message,
      durationMs,
    };
    if (err.result !== undefined) {
      out.result = err.result;
    }
    return out;
  } finally {
    clearTimeout(timer);
  }
}
