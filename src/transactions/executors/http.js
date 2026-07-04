'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { substitute } = require('../subst');
const { extract } = require('../extract');
const { phaseForError } = require('../phase');

const MAX_BODY = 1024 * 1024; // cap captured body at 1 MB

// One HTTP(S) request via Node core. Resolves { status, headers, body, timeMs }
// on a completed response, or { error: { phase, errno }, timeMs } on failure.
function requestOnce(urlStr, { method = 'GET', headers = {}, body, timeout = 15000 }, { httpImpl = http, httpsImpl = https, now = () => Date.now() } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(urlStr); } catch { resolve({ error: { phase: 'error', errno: 'EINVALIDURL' } }); return; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') { resolve({ error: { phase: 'error', errno: 'EPROTO' } }); return; }
    const lib = u.protocol === 'https:' ? httpsImpl : httpImpl;
    const t0 = now();
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve({ ...v, timeMs: now() - t0 }); };

    let req;
    try {
      req = lib.request(u, { method, headers, timeout }, (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { if (data.length < MAX_BODY) data += d; });
        res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: data }));
        res.on('error', (err) => done({ error: { phase: phaseForError(err), errno: err.code || 'ERES' } }));
      });
    } catch (err) {
      done({ error: { phase: phaseForError(err), errno: err.code || 'EREQ' } });
      return;
    }
    req.on('timeout', () => { try { req.destroy(); } catch { /* ignore */ } done({ error: { phase: 'timeout', errno: 'ETIMEDOUT' } }); });
    req.on('error', (err) => done({ error: { phase: phaseForError(err), errno: err.code || 'EREQ' } }));
    if (body != null && body !== '') { try { req.write(String(body)); } catch { /* handled by error */ } }
    req.end();
  });
}

// Runs a multi-step HTTP transaction. Substitutes {{secret:name}} + {{var}} in
// url/headers/body, asserts expect_status + expect_keyword, extracts variables
// for later steps, and records per-step timings. Stops at the first failing step
// and classifies the failure phase.
async function httpExecutor(test, deps = {}) {
  const cfg = test.config || {};
  const steps = Array.isArray(cfg.steps) ? cfg.steps : [];
  const secrets = test.secrets || {};
  const timeout = Number.isInteger(cfg.timeout_ms) ? cfg.timeout_ms : 15000;
  const vars = {};
  const stepTimings = [];
  let total = 0;

  if (!steps.length) return { status: 'error', latency_ms: 0, step_timings: [], detail: { phase: 'error', errno: 'NO_STEPS' } };

  for (let i = 0; i < steps.length; i += 1) {
    const s = steps[i] || {};
    const ctx = { secrets, vars };
    const url = substitute(s.url, ctx);
    const headers = {};
    if (s.headers) for (const [k, v] of Object.entries(s.headers)) headers[k] = substitute(v, ctx);
    const body = s.body != null ? substitute(s.body, ctx) : undefined;

    // eslint-disable-next-line no-await-in-loop
    const out = await requestOnce(url, { method: s.method || 'GET', headers, body, timeout }, deps);
    stepTimings.push(out.timeMs != null ? Math.round(out.timeMs) : null);
    total += out.timeMs || 0;

    if (out.error) {
      const status = out.error.phase === 'timeout' ? 'timeout' : (out.error.phase === 'error' ? 'error' : 'fail');
      return { status, latency_ms: Math.round(total), step_timings: stepTimings, step_failed: i, detail: { phase: out.error.phase, step: i, errno: out.error.errno || null } };
    }
    if (s.expect_status != null) {
      if (out.status !== Number(s.expect_status)) return { status: 'fail', latency_ms: Math.round(total), step_timings: stepTimings, step_failed: i, detail: { phase: 'http_status', step: i, errno: String(out.status) } };
    } else if (out.status >= 400) {
      return { status: 'fail', latency_ms: Math.round(total), step_timings: stepTimings, step_failed: i, detail: { phase: 'http_status', step: i, errno: String(out.status) } };
    }
    if (s.expect_keyword && !String(out.body || '').includes(String(s.expect_keyword))) {
      return { status: 'fail', latency_ms: Math.round(total), step_timings: stepTimings, step_failed: i, detail: { phase: 'keyword', step: i } };
    }
    if (s.extract && s.extract.name) {
      const v = extract(s.extract, out);
      if (v != null) vars[String(s.extract.name)] = v;
    }
  }

  return { status: 'ok', latency_ms: Math.round(total), step_timings: stepTimings };
}

module.exports = { httpExecutor, requestOnce };
