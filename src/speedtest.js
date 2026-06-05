'use strict';

// Active throughput ("speed test") against the BlueEye server: download then
// upload a sized blob and compute the achieved rate in Mbps. Self-contained —
// it talks only to the server the agent already trusts (no external service),
// so it works on air-gapped networks. Metadata only: byte counts and timings.
//
// Injectable (fetchImpl, now) so it can be tested without real transfers.

const DEFAULT_BYTES = 10 * 1024 * 1024; // 10 MiB each way
const MAX_BYTES = 200 * 1024 * 1024;

function mbps(bytes, ms) {
  if (!ms || ms <= 0) return null;
  return Number(((bytes * 8) / (ms / 1000) / 1e6).toFixed(2));
}

async function runSpeedtest({ serverUrl, token, bytes = DEFAULT_BYTES, fetchImpl = fetch, now = () => Date.now() }) {
  const size = Math.min(Math.max(Number(bytes) || DEFAULT_BYTES, 1024), MAX_BYTES);
  const base = String(serverUrl || '').replace(/\/+$/, '');
  let host = base;
  try { host = new URL(base).host; } catch { /* keep base */ }
  const auth = { Authorization: `Bearer ${token}` };

  const result = {
    type: 'speedtest', ts: new Date().toISOString(), target: host, ok: false,
    downMbps: null, upMbps: null, downBytes: 0, upBytes: 0, downMs: null, upMs: null,
  };

  // Download: time how long it takes to receive `size` bytes from the server.
  try {
    const t0 = now();
    const res = await fetchImpl(`${base}/speedtest/download?bytes=${size}`, { headers: auth });
    if (!res || !res.ok) {
      if (res && res.status === 401) { const e = new Error('token rejected'); e.code = 'TOKEN_REJECTED'; throw e; }
      throw new Error(`download HTTP ${res ? res.status : '?'}`);
    }
    const buf = Buffer.from(await res.arrayBuffer());
    const ms = now() - t0;
    result.downBytes = buf.length;
    result.downMs = ms;
    result.downMbps = mbps(buf.length, ms);
  } catch (err) {
    if (err.code === 'TOKEN_REJECTED') throw err;
    result.detail = `download: ${err.message}`;
    return result;
  }

  // Upload: time how long it takes to send `size` bytes to the server.
  try {
    const payload = Buffer.alloc(size, 0);
    const t0 = now();
    const res = await fetchImpl(`${base}/speedtest/upload`, {
      method: 'POST',
      headers: { ...auth, 'Content-Type': 'application/octet-stream' },
      body: payload,
    });
    if (!res || !res.ok) {
      if (res && res.status === 401) { const e = new Error('token rejected'); e.code = 'TOKEN_REJECTED'; throw e; }
      throw new Error(`upload HTTP ${res ? res.status : '?'}`);
    }
    const ms = now() - t0;
    result.upBytes = size;
    result.upMs = ms;
    result.upMbps = mbps(size, ms);
  } catch (err) {
    if (err.code === 'TOKEN_REJECTED') throw err;
    result.detail = `upload: ${err.message}`;
    return result;
  }

  result.ok = true;
  return result;
}

module.exports = { runSpeedtest, mbps };
