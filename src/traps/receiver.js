'use strict';

const dgram = require('dgram');
const { translateTrap } = require('./translate');
const { decodeTrap } = require('./decode');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Receives SNMP traps and turns them into device events — the same rows the
// syslog receiver produces, on the same ingest path, into the same table.
//
// The same start/drain/stats/stop contract as src/syslog/receiver.js, so the
// runtime drains both into one batch and the server has one route to maintain.
// A trap and a syslog line ARE the same thing arriving over a different socket.
//
// WHY THIS IS WORTH HAVING ON TOP OF SYSLOG. A trap usually arrives a second or
// two BEFORE the syslog line about the same event, because the device emits it
// from a different code path. And plenty of equipment — UPSes, older APs, PDUs
// — sends traps and no syslog at all.
//
// PORT 1162, NOT 162, for the same reason the syslog receiver uses 1514:
// binding below 1024 needs root, and a monitoring agent must not run as root to
// receive unauthenticated UDP.
//
// THE SENDER ALLOWLIST IS NOT OPTIONAL. An SNMPv2c trap is unauthenticated —
// anyone who can route a UDP packet to this port can claim to be any switch.
// The source address is all we have, so a trap is accepted ONLY from an address
// this agent actually polls (its `snmpTargets`). Everything else is counted and
// dropped. That is a weak check, and it is the strongest one v2c permits; SNMPv3
// traps, which can be authenticated, are a separate piece of work (they are
// counted as `v3` and dropped, never half-decoded).
//
// THE COMMUNITY, TOO, WHEN WE KNOW IT. A v1/v2c trap carries its community in
// clear text — no secret on the wire, but a second thing a spoofer has to get
// right, and the thing that tells "the switch" from "anything else on that
// address". When the polled device's community is known (the server hands the
// agent the one it polls with), a trap with a different community is counted
// as `communityMismatch`. It is only REFUSED (and counted as `badCommunity`)
// when `checkCommunity` is on — off by default, because many switches send
// traps with a different community than they are polled with, and refusing
// those would silently drop a whole device's traps. A device with no known
// community (a v3 target, or none assigned) is checked on address alone.

const MAX_TRAPS = 2000;
const DEFAULT_RATE_PER_SEC = 50;
const DEFAULT_BURST = 100;

// Folds repeats inside one drain window, exactly as the syslog receiver does.
function foldKey(row) {
  return [row.sourceIp, row.eventType, row.ifname || '', row.summary].join('\u0000');
}

function createTrapReceiver({
  port = 1162,
  bindAddress = '0.0.0.0',
  maxEvents = MAX_TRAPS,
  ratePerSec = DEFAULT_RATE_PER_SEC,
  burst = DEFAULT_BURST,
  logger = silentLogger,
  createSocket = () => dgram.createSocket({ type: 'udp4', reuseAddr: true }),
  // Decodes a datagram into { version, community, varbinds: [{ oid, value }] }.
  // The default is the pure BER decoder in ./decode.js; injectable for tests.
  decode = decodeTrap,
  // (sourceIp) => boolean. The polled-device allowlist, supplied by the
  // runtime from the server-assigned snmpTargets.
  isKnownSender = () => false,
  // (sourceIp) => community string | null. The community the runtime polls
  // that device with; null when it is not known (then only the address is
  // checked).
  expectedCommunity = () => null,
  checkCommunity = false,
  // (sourceIp, ifIndex) => ifName | null, from stage 02's topology poll.
  resolveIfName = null,
  now = () => Date.now(),
} = {}) {
  let socket = null;
  let buffer = new Map();
  let received = 0;
  let dropped = 0; // rate-limited
  let refused = 0; // not a device this agent polls
  let undecodable = 0;
  let badCommunity = 0; // refused: v1/v2c community differs from the polled one (checkCommunity on)
  let communityMismatch = 0; // differed from the polled one (refused or not)
  let v3 = 0; // SNMPv3 traps — out of scope, counted so they are not "garbage"
  let overflowed = 0;
  let lastAt = null;
  let bound = false;
  const buckets = new Map();

  function allow(sourceIp) {
    const t = now();
    let b = buckets.get(sourceIp);
    if (!b) {
      if (buckets.size >= 1024) return true;
      b = { tokens: burst, at: t };
      buckets.set(sourceIp, b);
    }
    b.tokens = Math.min(burst, b.tokens + ((t - b.at) / 1000) * ratePerSec);
    b.at = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  // Ingests one datagram. Never throws.
  function ingestDatagram(msg, sourceIp) {
    lastAt = now();

    // The allowlist FIRST, before any decoding: a hostile sender must not be
    // able to make this process do work by sending malformed packets.
    if (!isKnownSender(sourceIp)) {
      refused += 1;
      logger.debug(`trap from ${sourceIp} refused: not a device this agent polls`);
      return;
    }
    if (!allow(sourceIp)) {
      dropped += 1;
      return;
    }

    let decoded;
    try {
      decoded = decode(msg);
    } catch (err) {
      if (err && err.code === 'TRAP_V3_UNSUPPORTED') v3 += 1;
      else undecodable += 1;
      logger.debug(`trap from ${sourceIp} could not be decoded (${err.message})`);
      return;
    }

    if (decoded && typeof decoded.community === 'string') {
      let expected = null;
      try { expected = expectedCommunity(sourceIp); } catch { expected = null; }
      if (typeof expected === 'string' && expected && decoded.community !== expected) {
        communityMismatch += 1;
        if (checkCommunity) {
          badCommunity += 1;
          // Never log the community itself — it is the device's read secret.
          logger.debug(`trap from ${sourceIp} refused: community does not match the one this agent polls it with`);
          return;
        }
      }
    }

    let row;
    try {
      row = translateTrap({
        varbinds: decoded.varbinds,
        sourceIp,
        receivedAt: lastAt,
        resolveIfName: resolveIfName ? (ifIndex) => resolveIfName(sourceIp, ifIndex) : null,
      });
    } catch (err) {
      undecodable += 1;
      logger.debug(`trap from ${sourceIp} could not be translated (${err.message})`);
      return;
    }

    const key = foldKey(row);
    const existing = buffer.get(key);
    if (existing) {
      existing.occurrences += 1;
      existing.receivedAt = row.receivedAt;
      received += 1;
      return;
    }
    if (buffer.size >= maxEvents) {
      overflowed += 1;
      return;
    }
    buffer.set(key, row);
    received += 1;
  }

  async function start() {
    // No net-snmp needed: the decoder is pure (./decode.js).
    await new Promise((resolve, reject) => {
      socket = createSocket();
      socket.on('message', (msg, rinfo) => {
        ingestDatagram(msg, rinfo && rinfo.address ? String(rinfo.address).replace(/^::ffff:/, '') : 'unknown');
      });
      socket.on('error', (err) => logger.error(`trap socket error: ${err.message}`));
      socket.once('error', reject);
      socket.bind(port, bindAddress, () => { bound = true; resolve(); });
    });
    logger.info(`SNMP trap receiver listening on udp/${bindAddress}:${port}`);
    return { udp: true, port };
  }

  function drain() {
    const events = Array.from(buffer.values());
    buffer = new Map();
    return events;
  }

  function stats() {
    return {
      port,
      udp: bound,
      buffered: buffer.size,
      received,
      dropped,
      // Counted separately from `dropped` on purpose: "a switch nobody added is
      // shouting at us" and "a device we poll is shouting too fast" are
      // different problems with different fixes.
      refused,
      undecodable,
      badCommunity,
      communityMismatch,
      v3,
      checkCommunity: Boolean(checkCommunity),
      overflowed,
      senders: buckets.size,
      lastAt: lastAt ? new Date(lastAt).toISOString() : null,
    };
  }

  function stop() {
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
      socket = null;
    }
    bound = false;
  }

  return { start, drain, stats, stop, ingestDatagram };
}

module.exports = { createTrapReceiver, MAX_TRAPS };
