'use strict';

// REST client for agent-authenticated calls. The opaque token is sent as a
// Bearer credential (the same token used for the WebSocket).

// Throws a coded error for a non-OK agent response: 401 -> TOKEN_REJECTED
// (fatal upstream), any other failure -> HTTP_ERROR. `gerund`/`verb` keep the
// exact wording per call ("posting results" / "post results").
function assertOk(res, gerund, verb) {
  if (res.status === 401) {
    const err = new Error(`Agent token rejected (HTTP 401) while ${gerund}.`);
    err.code = 'TOKEN_REJECTED';
    throw err;
  }
  if (!res.ok) {
    const err = new Error(`Failed to ${verb}: HTTP ${res.status}.`);
    err.code = 'HTTP_ERROR';
    throw err;
  }
}

// Parses a JSON body, tolerating an empty/non-JSON response.
async function jsonOrEmpty(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

function createApiClient({ serverUrl, token, fetchImpl = fetch }) {
  async function postResults(results) {
    const res = await fetchImpl(`${serverUrl}/agents/results`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ results }),
    });
    assertOk(res, 'posting results', 'post results');
    return jsonOrEmpty(res);
  }

  // Fetches this agent's server-assigned monitoring config. Returns the
  // monitorConfig object (e.g. { source: 'proc' } or { source: 'snmp', ... }).
  async function getConfig() {
    const res = await fetchImpl(`${serverUrl}/agents/me/config`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assertOk(res, 'fetching config', 'fetch config');
    const body = await res.json();
    return body.monitorConfig || { source: 'proc' };
  }

  // Posts active-probe results (ping/tcp/dns/traceroute) for this agent.
  async function postProbeResults(results) {
    const res = await fetchImpl(`${serverUrl}/agents/probe-results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ results }),
    });
    assertOk(res, 'posting probe results', 'post probe results');
    return jsonOrEmpty(res);
  }

  // Posts active-discovery candidates found by this agent's scan.
  async function postDiscoveryResults(payload) {
    const res = await fetchImpl(`${serverUrl}/agents/discovery-results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    assertOk(res, 'posting discovery results', 'post discovery results');
    return jsonOrEmpty(res);
  }

  // Posts an active throughput ("speed test") result for this agent.
  async function postSpeedtest(result) {
    const res = await fetchImpl(`${serverUrl}/speedtest/results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ result }),
    });
    assertOk(res, 'posting speed-test result', 'post speed-test result');
    return jsonOrEmpty(res);
  }

  // Reports what this agent can do (e.g. { sources: ['proc','snmp'] }).
  async function postCapabilities(capabilities) {
    const res = await fetchImpl(`${serverUrl}/agents/me/capabilities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ capabilities }),
    });
    assertOk(res, 'reporting capabilities', 'report capabilities');
    return jsonOrEmpty(res);
  }

  return { postResults, getConfig, postCapabilities, postProbeResults, postDiscoveryResults, postSpeedtest };
}

module.exports = { createApiClient };
