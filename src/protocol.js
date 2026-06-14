'use strict';

// Agent ↔ server wire-contract version. Bumped only on a BREAKING change to the
// REST/WebSocket contract documented in PROTOCOL.md (additive, backward-compatible
// changes do NOT bump it). The agent declares this in the `/ws/agent` upgrade
// header `X-BlueEye-Protocol`; the server echoes its own in the `connected` frame.
// A mismatch is logged (warn) on both sides but is NEVER fatal.
//
// MUST equal blueeye-server/src/protocol.js PROTOCOL_VERSION.
const PROTOCOL_VERSION = 1;

module.exports = { PROTOCOL_VERSION };
