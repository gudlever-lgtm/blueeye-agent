'use strict';

const { sampleTraffic } = require('./trafficMonitor');
const { sampleSnmp } = require('./snmpMonitor');

// Builds a traffic sampler from a server-assigned monitor config. Both samplers
// share the same output shape, so callers don't care which one is used.
//   { source: 'proc' }                              -> local /proc/net/dev
//   { source: 'snmp', snmp: { host, ... } }         -> SNMP device counters
// Anything unknown falls back to proc.
function createSampler(monitorConfig = { source: 'proc' }) {
  const cfg = monitorConfig || {};
  if (cfg.source === 'snmp' && cfg.snmp) {
    return ({ intervalMs }) => sampleSnmp({ snmp: cfg.snmp, intervalMs });
  }
  return ({ intervalMs }) => sampleTraffic({ intervalMs });
}

module.exports = { createSampler };
