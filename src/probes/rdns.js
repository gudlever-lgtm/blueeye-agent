'use strict';

const dns = require('dns');
const net = require('net');
const { clampInt, round, fail } = require('./stats');

// Reverse-DNS probe: what does the address say it is called?
//
// The forward lookup (probes/dns.js) answers "does this name resolve". This
// answers the other direction, which is the one that breaks mail: a sending
// host whose IP has no PTR — or a PTR that does not lead back to the same
// address — is refused or greylisted by a large part of the internet, and
// nothing in a reachability test shows it. It is also how you find out whose
// address you are actually talking to when a name points somewhere unexpected.
//
// A hostname target is resolved first, so the probe can be pointed at either an
// address or a name and answers the same question about the address behind it.
//
// FORWARD-CONFIRMED is the verdict that matters (RFC 1912 §2.1, and what mail
// servers check): the PTR name must resolve back to the address it came from.
// A PTR that points at a name belonging to somebody else is worse than no PTR,
// because it looks fine until it is checked — so it is reported as its own
// state rather than folded into "ok".
async function rdnsProbe(spec, {
  lookup = dns.promises.lookup,
  reverse = dns.promises.reverse,
  resolve4 = dns.promises.resolve4,
  resolve6 = dns.promises.resolve6,
  now = () => Date.now(),
} = {}) {
  const host = String((spec && (spec.host || spec.target)) || '').trim();
  if (!host) return fail('rdns', host, 'invalid host');
  const timeoutMs = clampInt(spec && spec.timeoutMs, 5000, 100, 60000);

  const t0 = now();
  let address = host;
  // A name has to become an address before there is anything to reverse.
  if (!net.isIP(host)) {
    try {
      const r = await withTimeout(lookup(host), timeoutMs, 'forward lookup timed out');
      address = (r && (r.address || (Array.isArray(r) ? r[0] && r[0].address : null))) || null;
    } catch (err) {
      return { ...fail('rdns', host, `forward lookup failed: ${cause(err)}`), address: null };
    }
    if (!address) return { ...fail('rdns', host, 'forward lookup returned no address'), address: null };
  }

  let names;
  try {
    names = await withTimeout(reverse(address), timeoutMs, 'reverse lookup timed out');
  } catch (err) {
    // No PTR at all is a RESULT, not a broken probe: it is the answer a mail
    // administrator came here for. It is reported as a failed check with the
    // reason, because for the services that care, no PTR is a refusal.
    return {
      ...fail('rdns', host, ptrless(err) ? 'no PTR record for this address' : `reverse lookup failed: ${cause(err)}`),
      address,
      ptrNames: [],
      forwardConfirmed: false,
    };
  }
  const rttMs = round(now() - t0);
  const ptrNames = (names || []).map((n) => String(n)).slice(0, 8);
  if (!ptrNames.length) {
    return { ...fail('rdns', host, 'no PTR record for this address'), address, ptrNames: [], forwardConfirmed: false };
  }

  // Forward-confirm the first PTR name: does it lead back to this address?
  let forwardConfirmed = false;
  let confirmError = null;
  try {
    const resolver = net.isIPv6(address) ? resolve6 : resolve4;
    const back = await withTimeout(resolver(ptrNames[0]), timeoutMs, 'confirmation lookup timed out');
    forwardConfirmed = (back || []).some((a) => sameAddress(a, address));
  } catch (err) {
    confirmError = cause(err);
  }

  const detail = forwardConfirmed
    ? `${ptrNames[0]} (forward-confirmed)`
    : `${ptrNames[0]} — does not resolve back to ${address}${confirmError ? ` (${confirmError})` : ''}`;

  return {
    type: 'rdns',
    target: host,
    ok: true,
    attempts: 1,
    success: 1,
    rttMs,
    minMs: rttMs,
    maxMs: rttMs,
    jitterMs: 0,
    lossPct: 0,
    address,
    ptrNames,
    forwardConfirmed,
    detail,
  };
}

// A resolver's "this address has no PTR" comes back as an error code rather
// than an empty answer, and it means something different from a resolver that
// could not be reached.
function ptrless(err) {
  const code = err && err.code ? String(err.code) : '';
  return code === 'ENOTFOUND' || code === 'ENODATA';
}

const cause = (err) => String((err && (err.code || err.message)) || err);

// IPv6 can write the same address several ways, so compare as addresses rather
// than as strings where the platform gives us the means to.
function sameAddress(a, b) {
  if (a === b) return true;
  if (!net.isIPv6(a) || !net.isIPv6(b)) return false;
  try {
    const norm = (x) => new URL(`http://[${x}]`).hostname;
    return norm(a) === norm(b);
  } catch { return false; }
}

function withTimeout(promise, ms, message) {
  let timer = null;
  return Promise.race([
    promise.finally(() => { if (timer) clearTimeout(timer); }),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
      if (timer.unref) timer.unref();
    }),
  ]);
}

module.exports = { rdnsProbe };
