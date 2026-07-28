'use strict';

const vm = require('vm');

// Bounded evaluation of regular expressions that arrive from the SERVER — a
// probe's `expectBody` ("/pattern/flags") and a transaction step's
// `extract.pattern` — matched against response bodies of up to 8 MB.
//
// A pattern with nested quantifiers (the classic /^(a+)+$/) backtracks
// catastrophically, and the agent is single-threaded: one such match wedges the
// event loop for the rest of the process's life — no heartbeat, no reporting, no
// commands. That makes an ordinary probe a fleet-wide denial of service, so the
// agent bounds the match itself instead of trusting the pattern.
//
// Two bounds, because neither alone is enough:
//   1. the subject is truncated — backtracking blows up with the input length,
//      so a bounded subject keeps the worst case reachable at all;
//   2. the match runs inside a vm context with a wall-clock timeout. V8 checks
//      for interrupts while executing irregexp, so this genuinely aborts a
//      runaway match — unlike a setTimeout, which never gets a turn on a blocked
//      event loop.
// A timeout is reported as "no match": the probe fails its assertion, which is
// the same outcome an unmatched body already has, rather than taking the agent
// down.

const MAX_CHARS = 256 * 1024;
const TIMEOUT_MS = 250;

// Compiles a pattern, returning null instead of throwing on a malformed one so
// callers can degrade to a literal comparison.
function compile(pattern, flags = '') {
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

function clamp(text) {
  const s = String(text == null ? '' : text);
  return s.length > MAX_CHARS ? s.slice(0, MAX_CHARS) : s;
}

// Runs `re.exec(subject)` under the timeout. Returns the match array, or null on
// no match / a missing pattern / a timeout.
function safeExec(re, text, { timeoutMs = TIMEOUT_MS, maxChars = MAX_CHARS } = {}) {
  if (!re) return null;
  const s = maxChars === MAX_CHARS ? clamp(text) : String(text == null ? '' : text).slice(0, maxChars);
  try {
    return vm.runInNewContext('re.exec(s)', { re, s }, { timeout: timeoutMs });
  } catch {
    return null; // ERR_SCRIPT_EXECUTION_TIMEOUT (or anything else) => no match
  }
}

// Boolean form of safeExec, for a pure pass/fail assertion.
function safeTest(re, text, opts) {
  return safeExec(re, text, opts) !== null;
}

module.exports = { compile, safeExec, safeTest, MAX_CHARS, TIMEOUT_MS };
