'use strict';

const http = require('http');
const https = require('https');

// Windows-safe network teardown to run before a hard process.exit().
//
// On Windows, calling process.exit() while Node's built-in fetch (undici) still
// holds a keep-alive socket — or a core http/https agent has an idle pooled
// socket — races libuv's teardown of those handles and trips a fatal native
// assertion (`!(handle->flags & UV_HANDLE_CLOSING)`, src\win\async.c:94). The
// process aborts with a NON-ZERO exit code AFTER the work already succeeded: the
// `enroll` command stores the token and then crashes on the way out, so the
// Windows installer sees a non-zero exit and reports "enrollment failed" for an
// enrollment that actually worked (this is exactly the field failure this guards).
//
// Gracefully closing undici's global dispatcher (its keep-alive sockets + idle
// timers) and destroying the core http/https global agents drains those handles
// first, so the subsequent process.exit() has nothing left for libuv to race.
// Everything here is best-effort — teardown must never itself throw or hang.
async function closeNetworkHandles({
  // How to reach undici's global dispatcher. Node stores it on globalThis under a
  // versioned Symbol; fetch() installs it lazily, so it may be absent (no fetch
  // was ever made) — then there is nothing to close.
  getDispatcher = () => globalThis[Symbol.for('undici.globalDispatcher.1')],
  agents = [http.globalAgent, https.globalAgent],
  timeoutMs = 2000,
  setTimeoutFn = setTimeout,
} = {}) {
  let dispatcher = null;
  try { dispatcher = getDispatcher(); } catch { /* best-effort */ }

  if (dispatcher && typeof dispatcher.close === 'function') {
    // close() waits for in-flight requests (there are none by exit time) then
    // shuts every pooled socket. Cap the wait so a wedged socket can never hang a
    // one-shot CLI — we exit regardless once it resolves or the cap fires.
    const closed = Promise.resolve()
      .then(() => dispatcher.close())
      .catch(() => {});
    await Promise.race([
      closed,
      new Promise((resolve) => {
        const t = setTimeoutFn(resolve, timeoutMs);
        if (t && typeof t.unref === 'function') t.unref();
      }),
    ]);
  }

  for (const agent of agents) {
    try {
      if (agent && typeof agent.destroy === 'function') agent.destroy();
    } catch { /* best-effort */ }
  }
}

module.exports = { closeNetworkHandles };
