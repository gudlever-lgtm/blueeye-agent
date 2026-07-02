'use strict';

const { sampleTraffic } = require('./trafficMonitor');
const { sampleSnmp } = require('./snmpMonitor');
const { createNetflowCollector } = require('./netflow/collector');
const { createSflowCollector } = require('./sflow/collector');
const { silentLogger } = require('./logger');

// Wraps a UDP flow collector (netflow/sflow) as a sampler: start it in the
// background and drain() its aggregated snapshot each interval. Carries a
// .stop() for the socket lifecycle. A failed start (e.g. the UDP port is in
// use) is logged rather than swallowed.
function collectorSampler(collector, logger, kind) {
  Promise.resolve(collector.start()).catch((err) =>
    logger.warn(`flow collector failed to start: ${err.message}`));
  const sampler = async () => collector.drain();
  sampler.stop = () => collector.stop();
  // Surfaced by the runtime's "diagnose" handler so the dashboard can show the
  // collector's live receive/decode counters without draining them.
  sampler.kind = kind;
  sampler.stats = () => (typeof collector.stats === 'function' ? collector.stats() : null);
  return sampler;
}

// Builds a traffic sampler from a server-assigned monitor config. Every sampler
// is a callable `async ({ intervalMs }) => snapshot`; collector-backed ones
// (netflow/sflow) also carry a `.stop()` for their background lifecycle.
// Callers must call `sampler.stop?.()` when replacing or disposing a sampler.
//
//   { source: 'proc' }                          -> local /proc/net/dev (rate)
//   { source: 'snmp', snmp: { host, ... } }     -> device interface counters (rate)
//   { source: 'netflow', netflow: { port } }    -> NetFlow v5/v9/IPFIX collector
//   { source: 'sflow', sflow: { port } }        -> sFlow v5 collector (sampled)
//
// proc/snmp produce a per-interface byte-rate snapshot; netflow/sflow produce a
// flow summary (byPort/byProtocol/topTalkers). All are stored under the same
// `traffic` field; the server reads whichever fields are present. Unknown
// sources fall back to proc. Collector factories are injectable for tests.
function createSampler(
  monitorConfig = { source: 'proc' },
  { netflowFactory = createNetflowCollector, sflowFactory = createSflowCollector, logger = silentLogger } = {}
) {
  const cfg = monitorConfig || {};

  if (cfg.source === 'snmp' && cfg.snmp) {
    return ({ intervalMs }) => sampleSnmp({ snmp: cfg.snmp, intervalMs });
  }

  if (cfg.source === 'netflow') {
    const nf = cfg.netflow || {};
    return collectorSampler(netflowFactory({ port: nf.port || 2055, bindAddress: nf.bindAddress || '0.0.0.0' }), logger, 'netflow');
  }

  if (cfg.source === 'sflow') {
    const sf = cfg.sflow || {};
    return collectorSampler(sflowFactory({ port: sf.port || 6343, bindAddress: sf.bindAddress || '0.0.0.0' }), logger, 'sflow');
  }

  if (process.platform === 'darwin') {
    const { sampleTraffic: sampleTrafficDarwin } = require('./trafficMonitorDarwin');
    return ({ intervalMs }) => sampleTrafficDarwin({ intervalMs });
  }
  return ({ intervalMs }) => sampleTraffic({ intervalMs });
}

module.exports = { createSampler };
