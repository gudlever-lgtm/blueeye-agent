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

  return { postResults };
}

module.exports = { createApiClient };
