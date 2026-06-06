'use strict';

const dgram = require('dgram');
const { parseSflow } = require('./parse');
const { aggregateFlows } = require('../netflow/aggregate');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Listens for sFlow v5 datagrams on a UDP port (default 6343) and accumulates
// the rate-scaled flow records decoded from sampled packet headers. drain()
// returns an aggregated snapshot (same shape as the NetFlow collector) and
// clears the buffer. The socket factory is injectable for tests.
function createSflowCollector({
  port = 6343,
  bindAddress = '0.0.0.0',
  maxFlows = 100000,
  logger = silentLogger,
  createSocket = () => dgram.createSocket('udp4'),
} = {}) {
  let socket = null;
  let buffer = [];
  let received = 0;
  let dropped = 0;
  let decoded = 0; // cumulative flow records decoded (survives drain)
  let lastAt = null; // ms epoch of the last datagram seen (any datagram)
  let bound = false; // the UDP socket actually bound (vs failed/closed)

  function handlePacket(msg) {
    lastAt = Date.now();
    let parsed;
    try {
      parsed = parseSflow(msg);
    } catch (err) {
      dropped += 1;
      logger.debug(`sFlow: dropped a datagram (${err.message})`);
      return;
    }
    decoded += parsed.flows.length;
    for (const flow of parsed.flows) {
      if (buffer.length >= maxFlows) break;
      buffer.push(flow);
    }
    received += 1;
  }

  function start() {
    return new Promise((resolve, reject) => {
      socket = createSocket();
      socket.on('message', handlePacket);
      socket.on('error', (err) => logger.error(`sFlow socket error: ${err.message}`));
      socket.once('error', reject);
      try {
        socket.bind(port, bindAddress, () => {
          bound = true;
          logger.info(`sFlow collector listening on ${bindAddress}:${port}`);
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  function drain(opts) {
    const flows = buffer;
    buffer = [];
    const agg = aggregateFlows(flows, opts);
    return { source: 'sflow', datagrams: received, droppedDatagrams: dropped, sampled: true, ...agg };
  }

  function stop() {
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
      socket = null;
    }
    bound = false;
  }

  // Non-destructive health snapshot (does NOT clear the buffer) for the
  // dashboard "Diagnose" action: is the socket bound, how many datagrams have
  // arrived, how many flow records we decoded, and when we last heard anything.
  function stats() {
    return {
      listening: bound,
      datagrams: received,
      dropped,
      decodedFlows: decoded,
      bufferedFlows: buffer.length,
      lastDatagramAt: lastAt ? new Date(lastAt).toISOString() : null,
    };
  }

  function _feed(msg) { handlePacket(msg); }

  return { start, drain, stop, stats, _feed, get bufferedFlows() { return buffer.length; } };
}

module.exports = { createSflowCollector };
