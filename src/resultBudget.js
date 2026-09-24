'use strict';

// Keeps one traffic result under the size the server accepts.
//
// WHY. POST /agents/results refuses any single result over 65 535 bytes of
// JSON (the server's resultsValidation MAX_PAYLOAD_BYTES), and a refusal is a
// 400 for the WHOLE report — totals, interfaces, system metrics, everything
// measured that interval, gone. Nothing upstream bounds a flow summary by
// BYTES: 200 IPv6 flows with a VLAN and in/out interfaces measure ~57 KB on
// their own, and topTalkers, byPort and the sFlow counters come on top.
//
// WHAT. When a result is over RESULT_BUDGET_BYTES it is trimmed, in a fixed
// and logged order, until it fits — and a `truncated` marker says what went:
//
//   1. traffic.sflowCounters — the tail of the counter rotation. These are
//      handed back to the collector (see `removed`), so they go out next
//      interval rather than being lost.
//   2. traffic.flows         — sorted by bytes, so the tail is the SMALLEST
//      conversations. The totals are untouched: they were summed before any
//      list was cut, so the volume is still whole.
//   3. traffic.topTalkers    — likewise sorted, likewise from the tail.
//   4. traffic.byPort, traffic.byProtocol, traffic.interfaces — never reached
//      in practice; here so that no result is ever sent over the limit.
//
// If even that does not fit, the traffic detail is reduced to its scalars and
// totals. And if THAT does not fit, the caller is told (`oversize`) and must
// not send: a result the server will refuse is not worth the round trip.

const SERVER_MAX_RESULT_BYTES = 65535;
// Below the server's limit by enough for the marker itself and for a server
// that measures a little differently (it re-serialises what it parsed).
const RESULT_BUDGET_BYTES = 60000;

const TRIM_ORDER = [
  ['traffic', 'sflowCounters'],
  ['traffic', 'flows'],
  ['traffic', 'topTalkers'],
  ['traffic', 'byPort'],
  ['traffic', 'byProtocol'],
  ['traffic', 'interfaces'],
];

const bytesOf = (v) => Buffer.byteLength(JSON.stringify(v), 'utf8');

// Trims `value` (an object) to at most `maxBytes` of JSON by dropping items
// from the tail of the arrays named in `order` (each a key path), one array
// at a time, in that order. Never mutates its input: the containers on each
// path are copied before anything is cut.
//
// Returns { value, bytes, originalBytes, removed, marker, oversize }:
//   removed  — { 'a.b': [items dropped, in their original order] }
//   marker   — what was written under `markerKey`, or null when nothing was cut
//   oversize — true when it could not be made to fit at all
function fitToBudget(value, {
  maxBytes = RESULT_BUDGET_BYTES,
  order = TRIM_ORDER,
  markerKey = 'truncated',
  lastResort = null,
} = {}) {
  const originalBytes = bytesOf(value);
  if (originalBytes <= maxBytes) {
    return { value, bytes: originalBytes, originalBytes, removed: {}, marker: null, oversize: false };
  }

  const out = { ...value };
  const removed = {};
  const marker = { budgetBytes: maxBytes, originalBytes, removed: {} };
  out[markerKey] = marker;
  const copied = {};

  // The array at `path`, with every container on the way copied so the cut
  // does not reach the caller's object. Null when there is nothing there.
  function arrayAt(path) {
    let parent = out;
    for (let i = 0; i < path.length - 1; i += 1) {
      const next = parent[path[i]];
      if (!next || typeof next !== 'object' || Array.isArray(next)) return null;
      if (!Object.prototype.hasOwnProperty.call(copied, path.slice(0, i + 1).join('.'))) {
        parent[path[i]] = { ...next };
        copied[path.slice(0, i + 1).join('.')] = true;
      }
      parent = parent[path[i]];
    }
    const key = path[path.length - 1];
    if (!Array.isArray(parent[key]) || !parent[key].length) return null;
    parent[key] = parent[key].slice();
    return parent[key];
  }

  let bytes = bytesOf(out);
  for (const path of order) {
    if (bytes <= maxBytes) break;
    const arr = arrayAt(path);
    if (!arr) continue;
    const name = path.join('.');
    while (arr.length && bytes > maxBytes) {
      // Drop as many items from the tail as the overshoot needs (each item
      // plus its comma), then measure again: the marker's own count grows by
      // a digit now and then, so the estimate is checked, never trusted.
      const need = bytes - maxBytes;
      let freed = 0;
      let n = 0;
      while (n < arr.length && freed < need) {
        freed += bytesOf(arr[arr.length - 1 - n]) + 1;
        n += 1;
      }
      const cut = arr.splice(arr.length - n, n);
      removed[name] = cut.concat(removed[name] || []);
      marker.removed[name] = removed[name].length;
      bytes = bytesOf(out);
    }
  }

  if (bytes > maxBytes && typeof lastResort === 'function') {
    lastResort(out, marker);
    bytes = bytesOf(out);
  }
  return { value: out, bytes, originalBytes, removed, marker, oversize: bytes > maxBytes };
}

// The last resort for a traffic RESULT: keep what identifies and totals the
// measurement (its scalars and `totals`), drop every list. What a dashboard
// needs to say "traffic was measured, this much" survives; the breakdown for
// one interval does not.
function reduceTrafficToTotals(result, marker) {
  const t = result.traffic;
  if (!t || typeof t !== 'object') return;
  const kept = {};
  for (const [k, v] of Object.entries(t)) {
    if (v === null || typeof v !== 'object' || k === 'totals') kept[k] = v;
  }
  result.traffic = kept;
  marker.removed.trafficDetail = Object.keys(t).filter((k) => !(k in kept));
}

// Fits one traffic result for POST /agents/results.
function fitResult(result, { maxBytes = RESULT_BUDGET_BYTES } = {}) {
  return fitToBudget(result, { maxBytes, order: TRIM_ORDER, lastResort: reduceTrafficToTotals });
}

// One line for the log: "sflowCounters 12, flows 40".
function describeTrim(marker) {
  if (!marker) return '';
  return Object.entries(marker.removed)
    .map(([k, v]) => `${k.replace(/^traffic\./, '')} ${Array.isArray(v) ? v.join('/') : v}`)
    .join(', ');
}

module.exports = {
  fitResult,
  fitToBudget,
  describeTrim,
  bytesOf,
  RESULT_BUDGET_BYTES,
  SERVER_MAX_RESULT_BYTES,
  TRIM_ORDER,
};
