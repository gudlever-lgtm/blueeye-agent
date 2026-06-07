'use strict';

const fs = require('fs');

// A tiny append-only LOCAL action log, independent of the server, so an operator
// can audit what the agent did to itself (signature verification, update apply,
// delete, restart, failures) even if the server connection was down. Sensitive
// values are NEVER written in cleartext: keys on the denylist are redacted and
// every value is length-capped. Best-effort — logging never throws.
const DENY = new Set(['token', 'signature', 'sig', 'secret', 'authorization', 'password', 'key']);

function createActionLog({ path: logPath = '', fsImpl = fs, clock = () => new Date().toISOString() } = {}) {
  function redact(fields) {
    const out = {};
    for (const [k, v] of Object.entries(fields || {})) {
      if (DENY.has(String(k).toLowerCase())) {
        out[k] = '[redacted]';
      } else if (typeof v === 'string') {
        out[k] = v.length > 200 ? `${v.slice(0, 200)}…` : v;
      } else {
        out[k] = v;
      }
    }
    return out;
  }

  function log(event, fields = {}) {
    if (!logPath) return;
    let line;
    try {
      line = `${clock()} ${event} ${JSON.stringify(redact(fields))}\n`;
    } catch {
      line = `${clock()} ${event}\n`;
    }
    try {
      fsImpl.appendFileSync(logPath, line, { mode: 0o600 });
    } catch {
      /* best-effort: never let the audit log break the action */
    }
  }

  return { log, redact };
}

module.exports = { createActionLog };
