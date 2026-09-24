'use strict';

// Per-step PHASE timing for transaction executors.
//
// THE GAP THIS FILLS. Until now a step reported one number: the wall time from
// just before the request to the end of the response body. "Step 2 took 4200 ms"
// is true and useless — it does not say whether the network was slow, the name
// server was slow, the TLS handshake was slow, or the application sat on the
// request for four seconds. That is the first question every "the system is
// slow" ticket turns into, and the agent already had the answer in its hand: a
// Node socket emits `lookup`, `connect` and `secureConnect`, and the response
// callback fires when the first response byte lands.
//
// The phases are DELTAS between those moments, so they sum to the step time:
//
//   t0 ──lookup──▶ ──connect──▶ ──secureConnect──▶ ──headers──▶ ──end──▶
//      \_ dns _/   \_ tcp ___/   \_ tls _______/   \_ ttfb __/  \_ transfer _/
//
//   dns       name resolution
//   tcp       SYN → SYN-ACK → ACK. THIS IS THE NETWORK ROUND-TRIP TIME, measured
//             from above; a capture is not needed to read it.
//   tls       the handshake (https only; null for plain http)
//   ttfb      request sent → first response byte. Server think time, plus one RTT.
//   transfer  first byte → last byte. Body size over throughput.
//
// A null phase is not a zero. It means the moment never happened — no TLS on a
// plain http step, no dns for an IP literal, and none of the three on a step
// that reused a keep-alive socket (Node's global agent keeps connections alive,
// so step 2 to the same host usually has no handshake at all). `reused: true`
// says which of those it was, so a dashboard never renders a missing handshake
// as an instant one.
//
// Pure and clock-injected: no I/O of its own.

const PHASE_NAMES = Object.freeze(['dns', 'tcp', 'tls', 'ttfb', 'transfer']);

// The order the marks are expected in. Each phase measures from the most recent
// EARLIER mark that actually happened, so a missing middle mark (no TLS) widens
// its neighbour rather than losing the time altogether.
const MARK_ORDER = Object.freeze(['start', 'dns', 'tcp', 'tls', 'ttfb', 'end']);

function createPhaseTimer({ now = () => Date.now() } = {}) {
  const at = new Map([['start', now()]]);
  let reused = false;
  let address = null;
  let localPort = null;
  let remotePort = null;

  // First mark wins: a redirect or a retry inside one step must not overwrite
  // the handshake of the connection that actually carried it.
  function mark(name) {
    if (!at.has(name)) at.set(name, now());
  }

  // The socket was taken from the pool already connected, so there is no
  // handshake to measure on this step. Recorded rather than inferred from the
  // missing marks, because "no handshake happened" and "the handshake was not
  // observed" are different facts.
  function markReused() { reused = true; }

  // What the name actually resolved to, and which ports the connection used.
  // The address is worth reporting on its own (a step that goes somewhere
  // unexpected is a finding), and the local port is what lets a capture keep
  // only the packets belonging to THIS step.
  function markSocket({ address: addr = null, localPort: lp = null, remotePort: rp = null } = {}) {
    if (addr && !address) address = String(addr);
    if (Number.isInteger(lp) && lp > 0 && !localPort) localPort = lp;
    if (Number.isInteger(rp) && rp > 0 && !remotePort) remotePort = rp;
  }

  // Milliseconds between a mark and the latest preceding mark that happened.
  function deltaTo(name) {
    if (!at.has(name)) return null;
    const idx = MARK_ORDER.indexOf(name);
    for (let i = idx - 1; i >= 0; i -= 1) {
      const prev = MARK_ORDER[i];
      if (at.has(prev)) return Math.max(0, Math.round(at.get(name) - at.get(prev)));
    }
    return null;
  }

  // The finished phase record. `mark('end')` is implied so a caller that
  // forgets it still gets a transfer time rather than a null.
  function phases() {
    mark('end');
    const out = {
      dns: deltaTo('dns'),
      tcp: deltaTo('tcp'),
      tls: deltaTo('tls'),
      ttfb: deltaTo('ttfb'),
      transfer: deltaTo('end'),
    };
    // `end` is the transfer phase only when a first byte was actually seen.
    // On a step that failed during connect, `end` measures the failure, not a
    // body that never arrived — reporting that as `transfer` would invent a
    // download.
    if (!at.has('ttfb')) out.transfer = null;
    if (reused) out.reused = true;
    if (address) out.address = address;
    if (localPort) out.localPort = localPort;
    if (remotePort) out.remotePort = remotePort;
    return out;
  }

  return { mark, markReused, markSocket, phases, _at: () => new Map(at) };
}

// Attaches the phase marks to a Node socket. Shared by the http and tcp
// executors so both classify a handshake the same way. Returns the timer.
//
// A socket handed over already connected (keep-alive) emits none of these
// events, so it is recognised on arrival instead.
function watchSocket(timer, socket) {
  if (!socket || typeof socket.once !== 'function') return timer;
  if (socket.connecting === false && socket.remoteAddress) {
    timer.markReused();
    timer.markSocket({ address: socket.remoteAddress, localPort: socket.localPort, remotePort: socket.remotePort });
    return timer;
  }
  socket.once('lookup', (err, addr) => { if (!err) timer.markSocket({ address: addr }); timer.mark('dns'); });
  socket.once('connect', () => {
    timer.mark('tcp');
    timer.markSocket({ address: socket.remoteAddress, localPort: socket.localPort, remotePort: socket.remotePort });
  });
  socket.once('secureConnect', () => timer.mark('tls'));
  return timer;
}

module.exports = { createPhaseTimer, watchSocket, PHASE_NAMES };
