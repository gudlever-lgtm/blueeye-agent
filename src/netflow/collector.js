'use strict';

const dgram = require('dgram');
const { parseV5 } = require('./parseV5');
const { parseTemplated } = require('./parseTemplated');
const { aggregateFlows } = require('./aggregate');

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

// Listens for NetFlow export packets (v5 fixed-format, and v9/IPFIX
// template-based) on a UDP port and accumulates the flow records. drain()
// returns an aggregated snapshot of everything received since the last drain and
// clears the buffer — so each report covers one interval.
//
// v9/IPFIX templates are learned from Template FlowSets and remembered across
// packets in `templates`, so data records are decoded once their template is
// known.
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
  const templates = new Map(); // v9/IPFIX template cache, persisted across packets

  function handlePacket(msg) {
    let parsed;
    try {
      const version = Buffer.isBuffer(msg) && msg.length >= 2 ? msg.readUInt16BE(0) : 0;
      parsed = version === 9 || version === 10 ? parseTemplated(msg, templates) : parseV5(msg);
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
