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
    err.status = res.status;
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
  // `serverUrl` may be a function, so a client built once still follows the
  // agent when the live channel fails over to another way in to the same server
  // (config.serverUrls). Resolved per call rather than captured here.
  const base = () => String(typeof serverUrl === 'function' ? serverUrl() : serverUrl || '').replace(/\/+$/, '');
  async function postResults(results) {
    const res = await fetchImpl(`${base()}/agents/results`, {
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
    const res = await fetchImpl(`${base()}/agents/me/config`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assertOk(res, 'fetching config', 'fetch config');
    const body = await res.json();
    return body.monitorConfig || { source: 'proc' };
  }

  // The same call, returning the WHOLE body rather than just monitorConfig, so
  // a caller can read `snmpTargets` too. Kept separate from getConfig() rather
  // than changing its return shape: every existing caller of getConfig expects
  // a monitorConfig object, and widening it would be a silent contract change
  // in the one place the agent decides how it measures.
  async function getFullConfig() {
    const res = await fetchImpl(`${base()}/agents/me/config`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assertOk(res, 'fetching config', 'fetch config');
    return res.json();
  }

  // Submits one SNMP topology cycle: the forwarding/neighbour/VLAN tables read
  // from each switch this agent polls, plus a per-device error for the ones
  // that did not answer.
  async function postSnmpTopology(payload) {
    const res = await fetchImpl(`${base()}/agents/me/snmp-topology`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    assertOk(res, 'posting SNMP topology', 'post SNMP topology');
    return jsonOrEmpty(res);
  }

  // Submits one SNMP counter cycle: a snapshot of every interface counter on
  // each switch that asked for them. Its own endpoint rather than folded into
  // the topology POST, because the two run at different cadences and a counter
  // batch is an order of magnitude larger.
  async function postSnmpCounters(payload) {
    const res = await fetchImpl(`${base()}/agents/me/snmp-counters`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    assertOk(res, 'posting SNMP counters', 'post SNMP counters');
    return jsonOrEmpty(res);
  }

  // Posts active-probe results (ping/tcp/dns/traceroute) for this agent.
  async function postProbeResults(results) {
    const res = await fetchImpl(`${base()}/agents/probe-results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ results }),
    });
    assertOk(res, 'posting probe results', 'post probe results');
    return jsonOrEmpty(res);
  }

  // Posts active-discovery candidates found by this agent's scan.
  async function postDiscoveryResults(payload) {
    const res = await fetchImpl(`${base()}/agents/discovery-results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    assertOk(res, 'posting discovery results', 'post discovery results');
    return jsonOrEmpty(res);
  }

  // Posts an active throughput ("speed test") result for this agent.
  async function postSpeedtest(result) {
    const res = await fetchImpl(`${base()}/speedtest/results`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ result }),
    });
    assertOk(res, 'posting speed-test result', 'post speed-test result');
    return jsonOrEmpty(res);
  }

  // Posts device events (syslog now, SNMP traps later) this agent RECEIVED from
  // the network devices pointing at it. One batch per flush interval; the server
  // resolves each sender to a device and folds repeats.
  async function postDeviceEvents(events) {
    const res = await fetchImpl(`${base()}/agents/me/device-events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ events }),
    });
    assertOk(res, 'posting device events', 'post device events');
    return jsonOrEmpty(res);
  }

  // Reports what this agent can do (e.g. { sources: ['proc','snmp'] }).
  async function postCapabilities(capabilities) {
    const res = await fetchImpl(`${base()}/agents/me/capabilities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ capabilities }),
    });
    assertOk(res, 'reporting capabilities', 'report capabilities');
    return jsonOrEmpty(res);
  }

  return {
    postResults, getConfig, getFullConfig, postCapabilities, postProbeResults,
    postDiscoveryResults, postSpeedtest, postDeviceEvents, postSnmpTopology, postSnmpCounters,
  };
}

module.exports = { createApiClient };
