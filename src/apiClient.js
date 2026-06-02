'use strict';

// REST client for agent-authenticated calls. The opaque token is sent as a
// Bearer credential (the same token used for the WebSocket).
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

    if (res.status === 401) {
      const err = new Error('Agent token rejected (HTTP 401) while posting results.');
      err.code = 'TOKEN_REJECTED';
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`Failed to post results: HTTP ${res.status}.`);
      err.code = 'HTTP_ERROR';
      throw err;
    }

    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  // Fetches this agent's server-assigned monitoring config. Returns the
  // monitorConfig object (e.g. { source: 'proc' } or { source: 'snmp', ... }).
  async function getConfig() {
    const res = await fetchImpl(`${serverUrl}/agents/me/config`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) {
      const err = new Error('Agent token rejected (HTTP 401) while fetching config.');
      err.code = 'TOKEN_REJECTED';
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`Failed to fetch config: HTTP ${res.status}.`);
      err.code = 'HTTP_ERROR';
      throw err;
    }
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
    if (res.status === 401) {
      const err = new Error('Agent token rejected (HTTP 401) while posting probe results.');
      err.code = 'TOKEN_REJECTED';
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`Failed to post probe results: HTTP ${res.status}.`);
      err.code = 'HTTP_ERROR';
      throw err;
    }
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  // Reports what this agent can do (e.g. { sources: ['proc','snmp'] }).
  async function postCapabilities(capabilities) {
    const res = await fetchImpl(`${serverUrl}/agents/me/capabilities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ capabilities }),
    });
    if (res.status === 401) {
      const err = new Error('Agent token rejected (HTTP 401) while reporting capabilities.');
      err.code = 'TOKEN_REJECTED';
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`Failed to report capabilities: HTTP ${res.status}.`);
      err.code = 'HTTP_ERROR';
      throw err;
    }
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  return { postResults, getConfig, postCapabilities, postProbeResults };
}

module.exports = { createApiClient };
