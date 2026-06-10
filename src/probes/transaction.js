'use strict';

const { execFile } = require('child_process');
const { round, clampInt, fail } = require('./stats');
const { normalizeUrl } = require('./http');

const SENTINEL = '__BLUEEYE_TX__';
const MAX_BUFFER = 8 * 1024 * 1024;
const MAX_STEPS = 10;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

// Transaction probe (browser-free, curl-driven). Runs an ordered sequence of HTTP
// steps to simulate a user journey / scripted API call: each step issues a request
// and can assert the status and body, then extract a value (regex capture) into a
// variable that later steps reference as `{{name}}` in their URL, header or body —
// e.g. log in → capture a token → call an authenticated endpoint. Steps run in
// order and the transaction stops at the first failure.
//
// Reports a per-step waterfall (reusing `elements`: [{url,kind,status,bytes,ms}])
// plus totals (rtt = total journey time, bytes = total transferred, status = last
// step). Privacy by design: extracted values stay local and are never reported;
// only metadata (per-step URL, status, byte count, timing) leaves the agent.
async function transactionProbe(spec, { exec = execFile, now = () => Date.now() } = {}) {
  const steps = Array.isArray(spec && spec.steps) ? spec.steps.slice(0, MAX_STEPS) : [];
  if (!steps.length) return fail('transaction', String((spec && spec.name) || ''), 'no steps');
  const timeoutMs = clampInt(spec && spec.timeoutMs, 15000, 1000, 60000);

  const target = String(steps[0].url || spec.name || 'transaction').slice(0, 255);
  const vars = {};
  const elements = [];
  let totalMs = 0;
  let totalBytes = 0;
  let lastStatus = null;
  let failedAt = -1;
  let reason = null;

  for (let i = 0; i < steps.length; i += 1) {
    const step = steps[i] || {};
    const method = methodOf(step.method);
    const url = normalizeUrl(subst(step.url, vars));
    const label = `step ${i + 1} ${method}`;
    if (!url) {
      failedAt = i; reason = 'invalid url';
      elements.push({ url: String(step.url || '').slice(0, 255), kind: label, status: null, bytes: 0, ms: null });
      break;
    }
    // eslint-disable-next-line no-await-in-loop
    const out = await runStep(exec, url.href, method, subst(step.header, vars), subst(step.data, vars), timeoutMs, now);
    totalMs += out.timeMs || 0;
    totalBytes += out.bytes || 0;
    lastStatus = out.status;
    elements.push({ url: url.href, kind: label, status: out.status, bytes: out.bytes || 0, ms: out.timeMs });

    const ev = evalStep(out, step);
    if (!ev.ok) { failedAt = i; reason = ev.reason; break; }
    // Pull a value out of this response for later steps. Stored locally only.
    if (step.extract && step.extract.name && step.extract.pattern) {
      const v = extractVar(out, step.extract);
      if (v != null) vars[String(step.extract.name)] = v;
    }
  }

  const ok = failedAt === -1;
  return {
    type: 'transaction', target, ok,
    attempts: 1, success: ok ? 1 : 0,
    rttMs: round(totalMs), minMs: null, maxMs: null, jitterMs: null,
    lossPct: ok ? 0 : 100,
    status: lastStatus, bytes: totalBytes, elements,
    detail: (ok
      ? `${elements.length}/${steps.length} steps ok · ${round(totalMs)}ms`
      : `failed at step ${failedAt + 1}: ${reason || 'error'}`).slice(0, 255),
  };
}

function methodOf(m) {
  const v = String(m || 'GET').toUpperCase();
  return METHODS.has(v) ? v : 'GET';
}

// Substitutes {{name}} placeholders from previously extracted variables. Unknown
// names resolve to an empty string so a missing capture can't leak the literal.
function subst(str, vars) {
  if (str == null) return str;
  return String(str).replace(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g, (_m, name) => (vars[name] != null ? String(vars[name]) : ''));
}

// One request. Resolves { status, bytes, timeMs, headers, body, error? }.
function runStep(exec, href, method, header, data, timeoutMs, now) {
  return new Promise((resolve) => {
    const args = ['-sS', '-i', '-L', '--max-redirs', '5', '--max-time', String(Math.ceil(timeoutMs / 1000)), '-X', method];
    if (header) args.push('-H', String(header));
    if (data != null && data !== '') args.push('--data', String(data));
    args.push('-w', `\n${SENTINEL} %{http_code} %{size_download} %{time_total}`, '--url', href);
    exec('curl', args, { timeout: timeoutMs + 2000, maxBuffer: MAX_BUFFER }, (err, stdout, stderr) => {
      const parsed = parseOut(String(stdout || ''));
      if (parsed.status == null) {
        let why = 'curl failed';
        if (err) {
          if (err.code === 'ENOENT') why = 'curl not installed';
          else if (err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') why = 'response too large';
          else if (err.killed) why = 'curl timed out';
          else why = String(stderr || err.message || why).split('\n')[0].slice(0, 120).trim();
        }
        resolve({ status: null, bytes: 0, timeMs: null, headers: {}, body: '', error: why });
        return;
      }
      resolve({ status: parsed.status, bytes: parsed.bytes || 0, timeMs: parsed.timeMs, headers: parsed.headers, body: parsed.body });
    });
  });
}

// Splits curl -i output (final header block + body) from the trailing metrics line.
function parseOut(stdout) {
  const out = { status: null, bytes: null, timeMs: null, headers: {}, body: '' };
  const idx = stdout.lastIndexOf(`\n${SENTINEL} `);
  let head = stdout;
  if (idx !== -1) {
    head = stdout.slice(0, idx);
    const parts = stdout.slice(idx + 1 + SENTINEL.length + 1).split(' ');
    const code = Number.parseInt(parts[0], 10);
    if (Number.isInteger(code) && code > 0) out.status = code;
    const size = Number.parseInt(parts[1], 10);
    if (Number.isFinite(size)) out.bytes = size;
    const total = Number.parseFloat(parts[2]);
    if (Number.isFinite(total)) out.timeMs = round(total * 1000);
  }
  const re = /(^|\r?\n)HTTP\/\d/g;
  let m;
  let lastStart = 0;
  while ((m = re.exec(head)) !== null) lastStart = m.index + (m[1] ? m[1].length : 0);
  const block = head.slice(lastStart);
  const sep = block.search(/\r?\n\r?\n/);
  if (sep === -1) { out.headers = parseHeaders(block); return out; }
  out.headers = parseHeaders(block.slice(0, sep));
  out.body = block.slice(sep).replace(/^\r?\n\r?\n/, '');
  return out;
}

function parseHeaders(block) {
  const map = {};
  for (const raw of String(block).split(/\r?\n/)) {
    const c = raw.indexOf(':');
    if (c <= 0) continue;
    map[raw.slice(0, c).trim().toLowerCase()] = raw.slice(c + 1).trim();
  }
  return map;
}

// A step passes when the request completed and any configured assertions hold.
// With no assertions, a <400 status is a pass.
function evalStep(out, step) {
  if (out.status == null) return { ok: false, reason: out.error || 'no response' };
  if (step.expectStatus != null) {
    if (out.status !== Number(step.expectStatus)) return { ok: false, reason: `status ${out.status} ≠ ${step.expectStatus}` };
  } else if (out.status >= 400) {
    return { ok: false, reason: `status ${out.status}` };
  }
  if (step.expectBody) {
    if (!matchBody(out.body, step.expectBody)) return { ok: false, reason: 'body no match' };
  }
  return { ok: true };
}

function matchBody(body, expect) {
  const text = String(body || '');
  const re = /^\/(.+)\/([a-z]*)$/i.exec(String(expect));
  if (re) { try { return new RegExp(re[1], re[2]).test(text); } catch { /* literal */ } }
  return text.includes(String(expect));
}

// Extracts capture group 1 (or the whole match) of `pattern` from the response
// body (default) or its headers. Returns null when it doesn't match / is invalid.
function extractVar(out, ex) {
  const src = ex.from === 'header' ? Object.entries(out.headers).map(([k, v]) => `${k}: ${v}`).join('\n') : out.body;
  try {
    const m = new RegExp(String(ex.pattern)).exec(String(src || ''));
    if (!m) return null;
    return m[1] !== undefined ? m[1] : m[0];
  } catch { return null; }
}

module.exports = { transactionProbe, subst, extractVar, evalStep };
