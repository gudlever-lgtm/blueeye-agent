'use strict';

const { sampleTraffic } = require('./trafficMonitor');
const { sampleSnmp } = require('./snmpMonitor');
const { createNetflowCollector } = require('./netflow/collector');

// Builds a traffic sampler from a server-assigned monitor config. Every sampler
// is a callable `async ({ intervalMs }) => snapshot`; some (netflow) also carry
// a `.stop()` for their background lifecycle. Callers must call `sampler.stop?.()`
// when replacing or disposing a sampler.
//
//   { source: 'proc' }                          -> local /proc/net/dev (rate)
//   { source: 'snmp', snmp: { host, ... } }     -> device interface counters (rate)
//   { source: 'netflow', netflow: { port } }    -> NetFlow collector (per-port/protocol)
//
// proc/snmp produce a per-interface byte-rate snapshot; netflow produces a
// flow summary (byPort/byProtocol/topTalkers). Both are stored under the same
// `traffic` field; the server reads whichever fields are present. Unknown
// sources fall back to proc. The collector factory is injectable for tests.
function createSampler(monitorConfig = { source: 'proc' }, { netflowFactory = createNetflowCollector } = {}) {
  const cfg = monitorConfig || {};

  if (cfg.source === 'snmp' && cfg.snmp) {
    return ({ intervalMs }) => sampleSnmp({ snmp: cfg.snmp, intervalMs });
  }

  if (cfg.source === 'netflow') {
    const nf = cfg.netflow || {};
    const collector = netflowFactory({ port: nf.port || 2055, bindAddress: nf.bindAddress || '0.0.0.0' });
    // Start collecting immediately (bind happens in the background); each sample
    // drains whatever arrived in the interval.
    Promise.resolve(collector.start()).catch(() => {});
    const sampler = async () => collector.drain();
    sampler.stop = () => collector.stop();
    return sampler;
  }

  return ({ intervalMs }) => sampleTraffic({ intervalMs });
}

module.exports = { createSampler };
