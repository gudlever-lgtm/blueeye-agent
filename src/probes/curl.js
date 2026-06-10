'use strict';

const { execFile } = require('child_process');
const { clampInt, round, summarize, fail } = require('./stats');
const { normalizeUrl } = require('./http');

// Marker appended via curl's -w so we can split the transfer metrics off the end
// of the captured output without colliding with header/body text.
const SENTINEL = '__BLUEEYE_CURL__';
// Hard cap on captured response so a huge body can't OOM the agent. A body that
// exceeds this aborts the request and counts as a failed check (not a crash).
const MAX_BUFFER = 8 * 1024 * 1024;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

// HTTP(S) content-verification probe driven by the system `curl`. Where the
// `http` probe only answers "is it reachable + what status + cert expiry", this
// one verifies the *received traffic*: the HTTP status, the response body
// (substring or /regex/), the byte count, and a response header. curl fetches the
// body so the checks can run locally, but — privacy by design — only metadata
// leaves the agent: pass/fail, byte count, content-type and status. The body
// itself is never reported. The URL is passed via `--url`, so a crafted target
// can never be read as a curl flag, and nothing is run through a shell.
//
// An RTT (a "success") is recorded only when the request completed AND every
// configured expectation passed, so ok/loss% reflect end-to-end correctness, not
// merely that a socket opened. With no expectations a 2xx/3xx is healthy (4xx/5xx
// and transport errors count as loss), matching the `http` probe.
async function curlProbe(spec, { exec = execFile, now = () => Date.now() } = {}) {
  const raw = String((spec && (spec.url || spec.host || spec.target)) || '');
  const url = normalizeUrl(raw);
  if (!url) return fail('curl', raw, 'invalid url');

  const count = clampInt(spec && spec.count, 1, 1, 10);
  const timeoutMs = clampInt(spec && spec.timeoutMs, 10000, 1000, 60000);
  const method = methodOf(spec && spec.method);
  const expect = parseExpectations(spec);
  const args = buildArgs(url.href, method, timeoutMs, spec && spec.maxBytes);

  const rtts = [];
  let lastEval = null;
  let lastOut = null;
  for (let i = 0; i < count; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const out = await runCurl(exec, args, timeoutMs, now);
    const ev = evaluate(out, expect);
    lastOut = out;
    lastEval = ev;
    if (ev.ok) rtts.push(out.timeMs);
  }

  const extra = {
    status: lastOut && lastOut.status != null ? lastOut.status : null,
    bytes: lastOut && lastOut.bytes != null ? lastOut.bytes : null,
    contentType: lastOut && lastOut.contentType ? String(lastOut.contentType).slice(0, 120) : null,
    detail: (lastEval && lastEval.detail) || (lastOut && lastOut.error) || null,
  };
  return summarize('curl', url.href, rtts, count, extra);
}

function methodOf(m) {
  const v = String(m || 'GET').toUpperCase();
  return METHODS.has(v) ? v : 'GET';
}

// Builds the curl argument vector. `-i` includes response headers so a header
// expectation can be checked; `-L` follows redirects (we parse the final header
// block); `-w` appends the transfer metrics after the body.
function buildArgs(href, method, timeoutMs, maxBytes) {
  const args = [
    '-sS', '-i', '-L',
    '--max-time', String(Math.ceil(timeoutMs / 1000)),
    '--max-redirs', '5',
    '-X', method,
  ];
  const mb = Number(maxBytes);
  if (Number.isFinite(mb) && mb > 0) args.push('--max-filesize', String(Math.floor(mb)));
  args.push('-w', `\n${SENTINEL} %{http_code} %{size_download} %{time_total} %{content_type}`, '--url', href);
  return args;
}

// Runs curl once, never rejects. Resolves a normalized observation:
//   { ok, status, bytes, contentType, headers, body, timeMs, error? }
// `ok` here means "curl produced an HTTP response" (transport-level); the
// per-check verdict is computed later by evaluate().
function runCurl(exec, args, timeoutMs, now) {
  return new Promise((resolve) => {
    const t0 = now();
    exec('curl', args, { timeout: timeoutMs + 2000, maxBuffer: MAX_BUFFER }, (err, stdout, stderr) => {
      const wall = now() - t0;
      const parsed = parseCurlOutput(String(stdout || ''));
      if (parsed.status == null) {
        let reason = 'curl failed';
        if (err) {
          if (err.code === 'ENOENT') reason = 'curl not installed';
          else if (err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') reason = 'response too large';
          else if (err.killed) reason = 'curl timed out';
          else reason = firstLine(String(stderr || err.message)) || reason;
        }
        resolve({ ok: false, status: null, bytes: null, contentType: null, headers: {}, body: '', timeMs: wall, error: reason });
        return;
      }
      resolve({
        ok: true,
        status: parsed.status,
        bytes: parsed.bytes,
        contentType: parsed.contentType,
        headers: parsed.headers,
        body: parsed.body,
        timeMs: parsed.timeMs != null ? parsed.timeMs : wall,
      });
    });
  });
}

// Splits curl's output into { status, bytes, timeMs, contentType, headers, body }.
// The transfer metrics sit on the trailing SENTINEL line; content_type is last so
// it can carry spaces (e.g. "text/html; charset=utf-8").
function parseCurlOutput(stdout) {
  const out = { status: null, bytes: null, timeMs: null, contentType: null, headers: {}, body: '' };
  let head = stdout;
  const idx = stdout.lastIndexOf(`\n${SENTINEL} `);
  if (idx !== -1) {
    head = stdout.slice(0, idx);
    const line = stdout.slice(idx + 1 + SENTINEL.length + 1);
    const parts = line.split(' ');
    const code = Number.parseInt(parts[0], 10);
    if (Number.isInteger(code) && code > 0) out.status = code;
    const size = Number.parseInt(parts[1], 10);
    if (Number.isFinite(size)) out.bytes = size;
    const secs = Number.parseFloat(parts[2]);
    if (Number.isFinite(secs)) out.timeMs = round(secs * 1000);
    const ct = parts.slice(3).join(' ').trim();
    if (ct) out.contentType = ct;
  }
  const { headers, body } = splitHeadersBody(head);
  out.headers = headers;
  out.body = body;
  if (out.contentType == null && headers['content-type']) out.contentType = headers['content-type'];
  return out;
}

// Isolates the FINAL response's header block (the one right before the body, so
// -L redirect chains parse correctly) and returns { headers map, body string }.
function splitHeadersBody(head) {
  const re = /(^|\r?\n)HTTP\/\d/g;
  let m;
  let lastStart = 0;
  while ((m = re.exec(head)) !== null) lastStart = m.index + (m[1] ? m[1].length : 0);
  const block = head.slice(lastStart);
  const sep = block.search(/\r?\n\r?\n/);
  if (sep === -1) return { headers: parseHeaders(block), body: '' };
  return { headers: parseHeaders(block.slice(0, sep)), body: block.slice(sep).replace(/^\r?\n\r?\n/, '') };
}

// Header lines → { lowercased-name: value }. The status line is skipped.
function parseHeaders(block) {
  const map = {};
  for (const raw of String(block).split(/\r?\n/)) {
    const c = raw.indexOf(':');
    if (c <= 0) continue;
    const name = raw.slice(0, c).trim().toLowerCase();
    if (!name) continue;
    map[name] = raw.slice(c + 1).trim();
  }
  return map;
}

function firstLine(s) {
  return String(s || '').split('\n')[0].slice(0, 120).trim();
}

// Normalizes the operator's verification spec into matchers used locally.
function parseExpectations(spec) {
  const s = spec || {};
  const out = {};
  const status = Number(s.expectStatus != null ? s.expectStatus : s.status);
  if (Number.isInteger(status) && status >= 100 && status <= 599) out.status = status;
  const body = s.expectBody != null ? s.expectBody : s.body;
  if (typeof body === 'string' && body) out.body = toMatcher(body);
  const minBytes = Number(s.minBytes != null ? s.minBytes : s.expectMinBytes);
  if (Number.isFinite(minBytes) && minBytes >= 0) out.minBytes = Math.floor(minBytes);
  const header = parseHeaderExpect(s.expectHeader != null ? s.expectHeader : s.header);
  if (header) out.header = header;
  return out;
}

// A "/pattern/flags" string compiles to a RegExp; anything else is a literal
// substring. A malformed regex degrades to a literal so a bad spec can't throw.
function toMatcher(str) {
  const re = /^\/(.+)\/([a-z]*)$/i.exec(str);
  if (re) { try { return new RegExp(re[1], re[2]); } catch { /* fall through */ } }
  return { literal: str };
}

function parseHeaderExpect(h) {
  if (!h) return null;
  let name;
  let value = null;
  if (typeof h === 'string') {
    const c = h.indexOf(':');
    if (c >= 0) { name = h.slice(0, c).trim(); value = h.slice(c + 1).trim() || null; } else { name = h.trim(); }
  } else if (typeof h === 'object') {
    name = String(h.name || '').trim();
    value = h.value != null && String(h.value) ? String(h.value) : null;
  }
  if (!name || !HEADER_NAME_RE.test(name)) return null;
  return { name: name.toLowerCase(), value };
}

function matchBody(body, matcher) {
  const text = String(body || '');
  if (matcher instanceof RegExp) return matcher.test(text);
  return text.includes(matcher.literal);
}

// Presence (and optional case-insensitive value substring) check for a header.
function matchHeader(headers, expect) {
  const got = headers[expect.name];
  if (got == null) return false;
  if (expect.value == null) return true;
  return String(got).toLowerCase().includes(String(expect.value).toLowerCase());
}

// Computes the overall verdict + a human-readable, body-free explanation. Detail
// carries only metadata (status, byte count, content-type, header name, pass/fail
// marks) — never any matched body text.
function evaluate(out, expect) {
  const parts = [];
  let ok = out.ok;
  if (!out.ok) return { ok: false, detail: out.error || 'no response' };

  if (expect.status != null) {
    const pass = out.status === expect.status;
    ok = ok && pass;
    parts.push(pass ? `status ${out.status} ✓` : `status ${out.status} ≠ ${expect.status} ✗`);
  } else {
    const pass = out.status != null && out.status < 400;
    ok = ok && pass;
    parts.push(pass ? `status ${out.status}` : `status ${out.status} ✗`);
  }
  if (expect.body) {
    const pass = matchBody(out.body, expect.body);
    ok = ok && pass;
    parts.push(pass ? 'body matched ✓' : 'body no match ✗');
  }
  if (expect.minBytes != null) {
    const got = out.bytes ?? 0;
    const pass = got >= expect.minBytes;
    ok = ok && pass;
    parts.push(pass ? `${got}B ✓` : `${got}B < ${expect.minBytes} ✗`);
  }
  if (expect.header) {
    const pass = matchHeader(out.headers, expect.header);
    ok = ok && pass;
    parts.push(pass ? `${expect.header.name} ✓` : `${expect.header.name} ✗`);
  }
  return { ok, detail: parts.join(' · ').slice(0, 255) };
}

module.exports = { curlProbe, parseCurlOutput, splitHeadersBody, parseExpectations };
