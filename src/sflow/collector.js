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

  function handlePacket(msg) {
    let parsed;
    try {
      parsed = parseSflow(msg);
    } catch (err) {
      dropped += 1;
      logger.debug(`sFlow: dropped a datagram (${err.message})`);
      return;
    }
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
  }

  function _feed(msg) { handlePacket(msg); }

  return { start, drain, stop, _feed, get bufferedFlows() { return buffer.length; } };
}

module.exports = { createSflowCollector };
