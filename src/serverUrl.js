'use strict';

const { requestJson } = require('./httpsClient');
const { normalizeFingerprint } = require('./fingerprint');

// A server behind an "always HTTPS" proxy answers plain-http requests with a 301
// redirect to https. GET/POST survive it (they follow redirects), so enrollment
// works — but the WebSocket handshake does NOT follow redirects, and the
// Authorization header is dropped across an http→https hop, surfacing as a fatal
// 401. So an agent mistakenly configured with an http:// URL never connects.
//
// resolveEffectiveServerUrl probes the public GET /enroll/config once and, if the
// server redirects to https on the SAME host, adopts that https origin so the
// runtime uses wss:// and keeps its auth header. It only ever upgrades http→https
// on the same hostname — never downgrades, never follows a redirect to another
// host (which could be an open-redirect / MITM). On anything else (already https,
// a 200, an unreachable server, a cross-host or non-https redirect) it returns the
// URL unchanged and lets the normal runtime path handle/report it.
async function resolveEffectiveServerUrl({
  serverUrl,
  request = requestJson,
  fingerprint = '',
  logger = null,
  timeoutMs = 8000,
} = {}) {
  const url = safeUrl(serverUrl);
  if (!url || url.protocol !== 'http:') return serverUrl; // already https, or unparseable

  const base = String(serverUrl).replace(/\/+$/, '');
  let res;
  try {
    res = await request({ url: `${base}/enroll/config`, fingerprint: normalizeFingerprint(fingerprint), timeoutMs });
  } catch {
    return serverUrl; // unreachable over http — leave it; the runtime will report it
  }

  if (!res || res.status < 300 || res.status >= 400) return serverUrl; // not a redirect
  const loc = (res.headers && (res.headers.location || res.headers.Location)) || '';
  const target = safeUrl(loc);
  if (target && target.protocol === 'https:' && target.hostname === url.hostname) {
    if (logger && typeof logger.warn === 'function') {
      logger.warn(`Server redirects to HTTPS (${res.status}); using ${target.origin} instead of ${base}. Set BLUEEYE_SERVER_URL/BLUEEYE_PUBLIC_URL to the https URL to avoid this probe.`);
    }
    return target.origin; // uses the redirect's real host:port (e.g. :443)
  }
  return serverUrl;
}

function safeUrl(value) {
  try { return new URL(String(value)); } catch { return null; }
}

module.exports = { resolveEffectiveServerUrl };
