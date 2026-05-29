'use strict';

// Performs the one-time enrollment: POST /agents/enroll with the code and the
// agent-reported facts. Returns { ok: true, agentId, token } on success, or
// { ok: false, status, detail } on any non-201 (invalid/used/expired code).
async function enroll({ serverUrl, code, systemInfo, fetchImpl = fetch }) {
  const res = await fetchImpl(`${serverUrl}/agents/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      hostname: systemInfo.hostname,
      platform: systemInfo.platform,
      arch: systemInfo.arch,
    }),
  });

  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON response */
  }

  if (res.status === 201 && body && body.token) {
    return { ok: true, agentId: body.agentId, token: body.token };
  }
  return { ok: false, status: res.status, detail: body };
}

module.exports = { enroll };
