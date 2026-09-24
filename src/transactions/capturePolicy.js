'use strict';

// When is a transaction run worth keeping the packets for?
//
// A capture that runs on every tick is a standing collection, and a capture that
// only ever runs when somebody clicks is not there when the fault is. The answer
// in between is to capture into memory on every run and keep it only when the
// run went wrong — the packets for the one failure, nothing for the hundreds
// that were fine. Same posture as the evidence snapshot the server takes when an
// incident cluster opens: the evidence follows the event, not the calendar.
//
// Pure, so the rule is testable and reads the same to everyone.

const MODES = Object.freeze(['off', 'on_fault', 'always']);

function modeOf(test) {
  const raw = String((test && test.capture) || 'off').toLowerCase();
  return MODES.includes(raw) ? raw : 'off';
}

// Should a capture be STARTED for this run? (`off` never spawns tcpdump at all.)
function shouldCapture(test) {
  return modeOf(test) !== 'off';
}

// Should the packets be KEPT once the run has finished? Returns
// { keep, reason } — the reason is stored with the capture, so a row always
// says why it exists.
function shouldKeep(test, result) {
  const mode = modeOf(test);
  if (mode === 'off') return { keep: false, reason: null };
  if (mode === 'always') return { keep: true, reason: 'always' };

  const status = String((result && result.status) || '').toLowerCase();
  if (status && status !== 'ok') return { keep: true, reason: `status:${status}` };

  // A run that passed but was slow is the other half of "went wrong". The
  // threshold is the test's own alert threshold — a second number would be a
  // second definition of "too slow" to keep in step with the first.
  const cfg = (test && test.config) || {};
  const limit = cfg.thresholds && Number(cfg.thresholds.latency_ms);
  const latency = Number(result && result.latency_ms);
  if (Number.isFinite(limit) && limit > 0 && Number.isFinite(latency) && latency > limit) {
    return { keep: true, reason: `latency:${Math.round(latency)}ms>${Math.round(limit)}ms` };
  }

  return { keep: false, reason: null };
}

// How long the capture may run: the test's own timeout plus a margin for the
// handshake that precedes the first byte and the FIN that follows the last.
// Clamped by the runner as well — this is the request, not the guarantee.
function captureSeconds(test, { margin = 2, fallback = 15, max = 30 } = {}) {
  const cfg = (test && test.config) || {};
  const timeoutMs = Number(cfg.timeout_ms);
  const steps = Array.isArray(cfg.steps) && cfg.steps.length ? cfg.steps.length : 1;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return fallback;
  return Math.min(max, Math.max(1, Math.ceil((timeoutMs * steps) / 1000) + margin));
}

module.exports = { shouldCapture, shouldKeep, captureSeconds, modeOf, MODES };
