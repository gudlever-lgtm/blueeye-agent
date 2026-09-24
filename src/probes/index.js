'use strict';

const { tcpProbe } = require('./tcp');
const { dnsProbe } = require('./dns');
const { pingProbe } = require('./ping');
const { traceroute } = require('./traceroute');
const { tcptraceroute } = require('./tcptraceroute');
const { httpProbe } = require('./http');
const { curlProbe } = require('./curl');
const { pageloadProbe } = require('./pageload');
const { transactionProbe } = require('./transaction');
const { pathMtuProbe } = require('./pathmtu');
const { tlsProbe } = require('./tls');
const { rdnsProbe } = require('./rdns');
const { dhcpProbe } = require('./dhcp');

const RUNNERS = {
  tcp: tcpProbe, dns: dnsProbe, ping: pingProbe, traceroute, tcptraceroute,
  http: httpProbe, curl: curlProbe, pageload: pageloadProbe, transaction: transactionProbe,
  path_mtu: pathMtuProbe,
  // Neither of these shells out or needs a raw socket — they are Node's own dns
  // and tls, so they run anywhere the agent runs, including Windows and a
  // container with no extra tools installed.
  tls: tlsProbe, rdns: rdnsProbe,
  // A broadcast DHCPDISCOVER that collects every offer and never requests a
  // lease. Needs port 68, i.e. root or CAP_NET_BIND_SERVICE; says so when not.
  dhcp: dhcpProbe,
};

// Runs one probe by spec.type and returns a normalized result stamped with `ts`.
// Never throws: an unknown type or a runner error resolves to an ok:false result
// so a bad probe can't crash the agent. `deps` lets tests inject per-type fakes:
//   runProbe({ type:'tcp', host, port }, { tcp: { connect } })
async function runProbe(spec, deps = {}) {
  const type = String((spec && spec.type) || '').toLowerCase();
  const target = String((spec && (spec.host || spec.target || spec.iface)) || '');
  const base = { ts: new Date().toISOString() };
  const runner = RUNNERS[type];
  if (!runner) return { ...base, type: type || 'unknown', target, ok: false, error: `unknown probe type "${type}"` };
  try {
    return { ...base, ...(await runner(spec, deps[type] || {})) };
  } catch (err) {
    return { ...base, type, target, ok: false, error: err.message };
  }
}

module.exports = { runProbe, PROBE_TYPES: Object.keys(RUNNERS) };
