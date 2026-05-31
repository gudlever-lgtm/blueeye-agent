'use strict';

const dgram = require('dgram');
const { parseV5 } = require('./parseV5');
const { aggregateFlows } = require('./aggregate');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Listens for NetFlow v5 export packets on a UDP port and accumulates the flow
// records. drain() returns an aggregated snapshot of everything received since
// the last drain and clears the buffer — so each report covers one interval.
//
// The socket factory is injectable so tests can feed packets without real UDP.
function createNetflowCollector({
  port = 2055,
  bindAddress = '0.0.0.0',
  maxFlows = 100000,
  logger = silentLogger,
  createSocket = () => dgram.createSocket('udp4'),
} = {}) {
  let socket = null;
  let buffer = [];
  let received = 0;
  let dropped = 0;

  function handlePacket(msg) {
    let parsed;
    try {
      parsed = parseV5(msg);
    } catch (err) {
      dropped += 1;
      logger.debug(`NetFlow: dropped a packet (${err.message})`);
      return;
    }
    for (const flow of parsed.flows) {
      if (buffer.length >= maxFlows) break; // backpressure: cap memory
      buffer.push(flow);
    }
    received += 1;
  }

  function start() {
    return new Promise((resolve, reject) => {
      socket = createSocket();
      socket.on('message', handlePacket);
      socket.on('error', (err) => logger.error(`NetFlow socket error: ${err.message}`));
      socket.once('error', reject);
      try {
        socket.bind(port, bindAddress, () => {
          logger.info(`NetFlow collector listening on ${bindAddress}:${port}`);
          resolve();
        });
      } catch (err) {
        reject(err);
      }
    });
  }

  // Returns an aggregated snapshot of the buffered flows and clears the buffer.
  function drain(opts) {
    const flows = buffer;
    buffer = [];
    const agg = aggregateFlows(flows, opts);
    return { source: 'netflow', packets: received, droppedPackets: dropped, ...agg };
  }

  function stop() {
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
      socket = null;
    }
  }

  // Exposed for tests: feed a raw packet as if it arrived over UDP.
  function _feed(msg) { handlePacket(msg); }

  return { start, drain, stop, _feed, get bufferedFlows() { return buffer.length; } };
}

module.exports = { createNetflowCollector };
