'use strict';

const tls = require('tls');
const { clampInt, round, summarize, fail } = require('./stats');

// HTTP(S) synthetic probe. Issues `count` GET requests to a URL and reports
// reachability + request timing (DNS + connect + TLS + time-to-first-byte are
// folded into the measured request time), the final HTTP status, and — for
// https targets — the TLS certificate's days-to-expiry. A response with status
// < 400 counts as a healthy check; 4xx/5xx and network/timeout errors count as
// loss. Privacy by design: metadata only (status, timings, cert dates), never
// the response body. `fetchImpl` and `tlsConnect` are injectable so tests run
// with no network.
async function httpProbe(spec, { fetchImpl = globalThis.fetch, tlsConnect = tls.connect, now = () => Date.now() } = {}) {
  const url = normalizeUrl((spec && (spec.url || spec.host || spec.target)) || '');
  if (!url) return fail('http', String((spec && (spec.url || spec.host || spec.target)) || ''), 'invalid url');
  if (typeof fetchImpl !== 'function') return fail('http', url.href, 'no fetch implementation');

  const count = clampInt(spec.count, 1, 1, 10);
  const timeoutMs = clampInt(spec.timeoutMs, 10000, 100, 60000);
  const rtts = [];
  let status = null;
  for (let i = 0; i < count; i += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const t0 = now();
    try {
      // eslint-disable-next-line no-await-in-loop
      const res = await fetchImpl(url.href, { method: 'GET', redirect: 'follow', signal: controller.signal });
      status = typeof res.status === 'number' ? res.status : null;
      if (status != null && status < 400) rtts.push(now() - t0); // a <400 reply is a healthy check
    } catch { /* network error / timeout counts toward loss */ } finally {
      clearTimeout(timer);
    }
  }

  const extra = { status };
  // Best-effort TLS certificate inspection for https targets, on a separate short
  // connection so it never skews the request timing measured above.
  if (url.protocol === 'https:') {
    const cert = await inspectCert(url, timeoutMs, tlsConnect, now).catch(() => null);
    if (cert) {
      extra.certExpiryDays = cert.expiryDays;
      if (cert.detail) extra.detail = cert.detail;
    }
  }
  // summarize() sets ok from "at least one RTT recorded"; for HTTP an RTT is only
  // recorded on a <400 reply, so ok already means "reachable AND healthy status".
  return summarize('http', url.href, rtts, count, extra);
}

// Accepts a full http(s) URL or a bare host (defaulting to https). Returns a URL
// object, or null when the input can't be a valid http(s) URL.
function normalizeUrl(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // An explicit scheme is present — it must be http/https.
    if (!/^https?:\/\//i.test(s)) return null;
  } else {
    s = `https://${s}`; // bare host[:port][/path] → https
  }
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return u.hostname ? u : null;
}

// Opens a TLS connection just to read the peer certificate's expiry. Resolves
// { expiryDays, detail } or rejects; callers treat a rejection as "no cert info".
function inspectCert(url, timeoutMs, tlsConnect, now) {
  return new Promise((resolve, reject) => {
    const port = url.port ? Number(url.port) : 443;
    let socket;
    let done = false;
    const finish = (fn, arg) => {
      if (done) return;
      done = true;
      if (socket) { try { socket.destroy(); } catch { /* ignore */ } }
      fn(arg);
    };
    try {
      socket = tlsConnect({ host: url.hostname, port, servername: url.hostname, timeout: timeoutMs }, () => {
        const cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
        if (!cert || !cert.valid_to) return finish(reject, new Error('no certificate'));
        const expiry = new Date(cert.valid_to).getTime();
        const expiryDays = Number.isFinite(expiry) ? round((expiry - now()) / 86400000) : null;
        const issuer = cert.issuer && (cert.issuer.O || cert.issuer.CN);
        const detail = expiryDays != null ? `cert ${expiryDays}d${issuer ? ` · ${issuer}` : ''}` : null;
        finish(resolve, { expiryDays, detail });
      });
    } catch (err) { return reject(err); }
    socket.once('error', (err) => finish(reject, err));
    socket.once('timeout', () => finish(reject, new Error('tls timeout')));
  });
}

module.exports = { httpProbe, normalizeUrl };
