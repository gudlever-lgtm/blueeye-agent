'use strict';

const { execFile } = require('child_process');
const { round, clampInt, fail } = require('./stats');
const { normalizeUrl } = require('./http');

const SENTINEL = '__BLUEEYE_PL__';
const MAX_BUFFER = 8 * 1024 * 1024;
const DEFAULT_MAX_ELEMENTS = 20;
const HARD_MAX_ELEMENTS = 40;

// Page-load probe (browser-free). Fetches a page with `curl`, parses its linked
// sub-resources (scripts, stylesheets, images), then times a fetch of each — a
// resource "waterfall" with per-element status/size/timing, plus page totals
// (element count, total weight, document time, total load time). It can't observe
// real DOM/`load` events (no JS engine), so "total load" approximates the browser
// model: document time + the wall time to fetch all assets in parallel.
//
// Privacy by design: bodies are fetched only to measure them (resource bodies are
// discarded; the document body is parsed locally for links) — the agent reports
// metadata only (per-resource URL, status, byte count, timing), never contents.
async function pageloadProbe(spec, { exec = execFile, now = () => Date.now() } = {}) {
  const raw = String((spec && (spec.url || spec.host || spec.target)) || '');
  const url = normalizeUrl(raw);
  if (!url) return fail('pageload', raw, 'invalid url');

  const timeoutMs = clampInt(spec && spec.timeoutMs, 15000, 1000, 60000);
  const maxElements = clampInt(spec && spec.maxElements, DEFAULT_MAX_ELEMENTS, 1, HARD_MAX_ELEMENTS);

  // 1. The document itself (keep the body so we can parse out its sub-resources).
  const doc = await fetchResource(exec, url.href, timeoutMs, true);
  if (doc.status == null) {
    return { type: 'pageload', target: url.href, ok: false, attempts: 1, success: 0, rttMs: null, minMs: null, maxMs: null, jitterMs: null, lossPct: 100, status: null, bytes: 0, elements: [], detail: doc.error || 'document fetch failed' };
  }

  const elements = [{ url: url.href, kind: 'document', status: doc.status, bytes: doc.bytes || 0, ms: doc.totalMs }];
  const resources = extractResources(doc.body, url, maxElements);

  // 2. Fetch the sub-resources in parallel and measure the wall time of that phase
  //    (the browser-like "fetch the assets" step). Bodies are discarded.
  const t0 = now();
  const fetched = await Promise.all(resources.map((r) => fetchResource(exec, r.url, timeoutMs, false)));
  const resourcePhaseMs = round(now() - t0);
  let failed = 0;
  fetched.forEach((res, i) => {
    if (res.status == null || res.status >= 400) failed += 1;
    elements.push({ url: resources[i].url, kind: resources[i].kind, status: res.status, bytes: res.bytes || 0, ms: res.totalMs });
  });

  const totalBytes = elements.reduce((s, e) => s + (e.bytes || 0), 0);
  const totalMs = round((doc.totalMs || 0) + resourcePhaseMs);
  const ok = doc.status < 400;
  // ok = document is healthy; loss% = share of sub-resources that failed; rtt =
  // total page-load time. This keeps pageload consistent with the other probes for
  // the health/availability model.
  return {
    type: 'pageload', target: url.href, ok,
    attempts: 1, success: ok ? 1 : 0,
    rttMs: totalMs, minMs: null, maxMs: null, jitterMs: null,
    lossPct: resources.length ? round((failed / resources.length) * 100) : 0,
    status: doc.status, bytes: totalBytes, elements,
    detail: `${elements.length} elements · ${fmtKB(totalBytes)} · doc ${round(doc.totalMs)}ms · total ${totalMs}ms${failed ? ` · ${failed} failed` : ''}`.slice(0, 255),
  };
}

// One curl fetch. Resolves { status, bytes, totalMs, ttfbMs, contentType, body, error }.
// With keepBody=false the body is sent to /dev/null (timing/size only).
function fetchResource(exec, href, timeoutMs, keepBody) {
  return new Promise((resolve) => {
    const args = ['-sS', '-L', '--max-redirs', '5', '--max-time', String(Math.ceil(timeoutMs / 1000))];
    if (!keepBody) args.push('-o', '/dev/null');
    args.push('-w', `\n${SENTINEL} %{http_code} %{size_download} %{time_total} %{time_starttransfer} %{content_type}`, '--url', href);
    exec('curl', args, { timeout: timeoutMs + 2000, maxBuffer: MAX_BUFFER }, (err, stdout, stderr) => {
      const parsed = parseOut(String(stdout || ''));
      if (parsed.status == null) {
        let reason = 'curl failed';
        if (err) {
          if (err.code === 'ENOENT') reason = 'curl not installed';
          else if (err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') reason = 'response too large';
          else if (err.killed) reason = 'curl timed out';
          else reason = firstLine(String(stderr || err.message)) || reason;
        }
        resolve({ status: null, bytes: 0, totalMs: null, ttfbMs: null, contentType: null, body: '', error: reason });
        return;
      }
      resolve({ status: parsed.status, bytes: parsed.bytes || 0, totalMs: parsed.totalMs, ttfbMs: parsed.ttfbMs, contentType: parsed.contentType, body: keepBody ? parsed.body : '' });
    });
  });
}

// Splits curl's body from the trailing SENTINEL metrics line.
function parseOut(stdout) {
  const out = { status: null, bytes: null, totalMs: null, ttfbMs: null, contentType: null, body: '' };
  const idx = stdout.lastIndexOf(`\n${SENTINEL} `);
  if (idx === -1) return out;
  out.body = stdout.slice(0, idx);
  const parts = stdout.slice(idx + 1 + SENTINEL.length + 1).split(' ');
  const code = Number.parseInt(parts[0], 10);
  if (Number.isInteger(code) && code > 0) out.status = code;
  const size = Number.parseInt(parts[1], 10);
  if (Number.isFinite(size)) out.bytes = size;
  const total = Number.parseFloat(parts[2]);
  if (Number.isFinite(total)) out.totalMs = round(total * 1000);
  const ttfb = Number.parseFloat(parts[3]);
  if (Number.isFinite(ttfb)) out.ttfbMs = round(ttfb * 1000);
  const ct = parts.slice(4).join(' ').trim();
  if (ct) out.contentType = ct;
  return out;
}

// Pulls sub-resource URLs from the HTML: <script src>, <img src>, and
// <link rel=stylesheet href>. Relative URLs resolve against the page URL;
// only http(s) are kept, de-duplicated, capped at `max`. Regex-based (no DOM
// parser) to honour the single-dependency rule.
function extractResources(html, base, max) {
  const out = [];
  const seen = new Set();
  const push = (rawUrl, kind) => {
    if (out.length >= max) return;
    let u;
    try { u = new URL(rawUrl, base); } catch { return; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
    const href = u.href.slice(0, 255);
    if (seen.has(href)) return;
    seen.add(href);
    out.push({ url: href, kind });
  };
  let m;
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi;
  while ((m = scriptRe.exec(html)) !== null) push(m[1], 'script');
  const imgRe = /<img\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi;
  while ((m = imgRe.exec(html)) !== null) push(m[1], 'img');
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html)) !== null) {
    if (!/\brel\s*=\s*["']?[^"'>]*stylesheet/i.test(m[1])) continue;
    const h = /\bhref\s*=\s*["']?([^"'\s>]+)/i.exec(m[1]);
    if (h) push(h[1], 'css');
  }
  return out.slice(0, max);
}

function fmtKB(bytes) {
  const kb = (Number(bytes) || 0) / 1024;
  if (kb >= 1024) return `${round(kb / 1024)} MB`;
  return `${round(kb)} KB`;
}

function firstLine(s) {
  return String(s || '').split('\n')[0].slice(0, 120).trim();
}

module.exports = { pageloadProbe, extractResources, parseOut };
