'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { normalizeFingerprint } = require('./fingerprint');

// Compares a peer certificate against an expected SHA-256 fingerprint. Returns
// an Error on a mismatch, or undefined to accept (incl. when no pin is set).
//
// We pin the EXACT leaf certificate rather than trusting the CA chain — that's
// stricter for our case (an on-prem server or reverse proxy, often with a
// private/self-signed CA). Because Node skips checkServerIdentity when
// rejectUnauthorized is false, callers verify on the socket's 'secureConnect'
// (see verifyPeerOrDestroy) instead of via checkServerIdentity.
function checkPin(expected) {
  const want = normalizeFingerprint(expected);
  return (_host, cert) => {
    if (!want) return undefined; // no pin configured -> accept
    const got = normalizeFingerprint(cert && cert.fingerprint256);
    if (!got || got !== want) {
      const err = new Error(`Server certificate fingerprint mismatch (expected ${want}, got ${got || 'none'})`);
      err.code = 'CERT_FINGERPRINT_MISMATCH';
      return err;
    }
    return undefined;
  };
}

// Verifies a freshly-connected TLS socket against the pin and destroys it (with
// a coded error) on mismatch — before any request body / auth header is sent.
function verifyPeerOrDestroy(socket, expected) {
  const cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate() : null;
  const err = checkPin(expected)(socket.servername || '', cert);
  if (err) socket.destroy(err);
}

// Minimal JSON/binary request over core http/https. When `fingerprint` is set
// and the URL is https, the server certificate is pinned to it. `body` may be a
// string or Buffer/TypedArray/ArrayBuffer (sent as-is, byte for byte) or a
// plain object (JSON-encoded). Resolves { status, raw, json, buffer, headers }:
// `buffer` is the exact response bytes (binary-safe), `raw`/`json` its utf8
// view, `headers` Node's lower-cased response-header object.
function requestJson({ url, method = 'GET', headers = {}, body, fingerprint, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(url);
    } catch (err) {
      reject(err);
      return;
    }
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    let payload = null;
    if (body != null) {
      if (typeof body === 'string' || Buffer.isBuffer(body)) payload = body;
      else if (ArrayBuffer.isView(body)) payload = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
      else if (body instanceof ArrayBuffer) payload = Buffer.from(body);
      else payload = JSON.stringify(body);
    }

    const opts = {
      method,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers: {
        ...(payload != null ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    };
    const wantFp = isHttps ? normalizeFingerprint(fingerprint) : '';
    if (wantFp) opts.rejectUnauthorized = false; // trust = the pinned fingerprint, verified on secureConnect

    const req = lib.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        const raw = buffer.toString('utf8');
        let json = null;
        try { json = raw ? JSON.parse(raw) : null; } catch { /* non-JSON */ }
        resolve({ status: res.statusCode, raw, json, buffer, headers: res.headers || {} });
      });
    });
    // Pin the leaf cert as soon as the TLS handshake completes, before the
    // request body (which may carry the enrollment code) is flushed.
    if (wantFp) {
      req.on('socket', (socket) => socket.on('secureConnect', () => verifyPeerOrDestroy(socket, wantFp)));
    }
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('request timed out')); });
    if (payload != null) req.write(payload);
    req.end();
  });
}

// Adapts requestJson to the subset of the fetch() interface the agent uses
// (status, ok, headers.get(), json(), text(), arrayBuffer()), so every module
// can pin transparently — including the binary consumers: selfUpdate needs
// arrayBuffer() + the X-Release-* headers, speedtest needs arrayBuffer() and a
// verbatim Buffer upload.
function makePinnedFetch(fingerprint) {
  return async (url, { method = 'GET', headers = {}, body } = {}) => {
    const { status, raw, buffer, headers: resHeaders } = await requestJson({ url, method, headers, body, fingerprint });
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: {
        get(name) {
          const v = resHeaders[String(name).toLowerCase()];
          if (v == null) return null;
          return Array.isArray(v) ? v.join(', ') : String(v);
        },
      },
      async json() { return raw ? JSON.parse(raw) : null; },
      async text() { return raw; },
      async arrayBuffer() { return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength); },
    };
  };
}

module.exports = { requestJson, checkPin, verifyPeerOrDestroy, makePinnedFetch };
