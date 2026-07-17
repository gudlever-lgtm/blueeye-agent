'use strict';

// Agent-side READ-ONLY evidence collector (Fase 6). Defense in depth: even though
// the server sends an allowlisted evidence command (and signs it), the AGENT
// independently enforces its OWN read-only allowlist — it refuses to run anything
// not on this list, so a compromised/mistaken server can never make the agent
// perform a write/mutate action for "evidence". This mirrors the install-tool
// model, where the agent only installs tools on its own allowlist.
//
// Every item is a bounded, read-only diagnostic. Collectors are injected (the
// runtime wires the real /proc reads etc.) so this stays unit-testable.

// MUST match blueeye-server src/evidence/commandAllowlist.js.
const READ_ONLY_ITEMS = Object.freeze(['iface.counters', 'arp.table', 'snmp.reads', 'agent.state']);

function isAllowed(name) {
  return READ_ONLY_ITEMS.includes(name);
}

function withTimeout(promise, ms) {
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_resolve, reject) => {
      const t = setTimeout(() => reject(new Error('collector timeout')), ms);
      if (t.unref) t.unref();
    }),
  ]);
}

// `collectors` maps an allowlisted item name → async () => text. Anything not on
// the allowlist is REFUSED without invoking any collector.
function createEvidenceCollector({ collectors = {}, timeoutMs = 5000 } = {}) {
  async function collectOne(name) {
    if (!isAllowed(name)) {
      return { name, status: 'refused', payload: 'refused: not on the agent read-only evidence allowlist' };
    }
    const fn = collectors[name];
    if (typeof fn !== 'function') {
      return { name, status: 'ok', payload: '(no collector configured on this agent)' };
    }
    try {
      const text = await withTimeout(fn(), timeoutMs);
      return { name, status: 'ok', payload: String(text == null ? '' : text) };
    } catch (err) {
      return { name, status: 'timeout', payload: `error: ${err && err.message}` };
    }
  }

  // Collects the requested items (or the full read-only set when none given).
  // Partial results are valid — each item carries its own status.
  async function collect(names) {
    const list = Array.isArray(names) && names.length ? names : READ_ONLY_ITEMS;
    const items = [];
    for (const name of list) {
      items.push(await collectOne(name)); // eslint-disable-line no-await-in-loop
    }
    return items;
  }

  return { collect, collectOne, isAllowed };
}

module.exports = { createEvidenceCollector, isAllowed, READ_ONLY_ITEMS };
