'use strict';

const { loadNetSnmp } = require('../snmp/session');

const dgram = require('dgram');
const { translateTrap } = require('./translate');

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
// traps, which can be authenticated, are a separate piece of work.

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
  // Decodes a datagram into { varbinds: [{ oid, value }] }. Injected so the
  // tests never need net-snmp, and so a host without the optional dependency
  // fails at START with a clear reason rather than on the first packet.
  decode = null,
  // (sourceIp) => boolean. The polled-device allowlist, supplied by the
  // runtime from the server-assigned snmpTargets.
  isKnownSender = () => false,
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
  let overflowed = 0;
  let lastAt = null;
  let bound = false;
  const buckets = new Map();

  function defaultDecode(msg) {
    const net = loadNetSnmp('SNMP traps');
    // net-snmp exposes the same message parser the trap receiver uses. A v1
    // trap is converted to the v2 varbind shape by the library, so there is one
    // path here rather than two.
    const parsed = net.Message ? net.Message.createFromBuffer(msg) : null;
    const pdu = parsed && parsed.pdu;
    if (!pdu || !Array.isArray(pdu.varbinds)) {
      const err = new Error('not an SNMP trap');
      err.code = 'TRAP_MALFORMED';
      throw err;
    }
    return { varbinds: pdu.varbinds.map((vb) => ({ oid: vb.oid, value: vb.value })) };
  }

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
      decoded = (decode || defaultDecode)(msg);
    } catch (err) {
      undecodable += 1;
      logger.debug(`trap from ${sourceIp} could not be decoded (${err.message})`);
      return;
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
    // Fail at START, not on the first packet: a host without net-snmp should
    // say so in the log at boot, when somebody is looking, rather than silently
    // discarding every trap.
    if (!decode) loadNetSnmp('SNMP traps');
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
