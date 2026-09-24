'use strict';

// Derives a capture filter FROM THE TEST, and refuses anything else.
//
// THIS IS WHY THE CAPTURE PATH HAS NO BPF GRAMMAR TO VALIDATE. Nobody types a
// filter. The agent is about to generate the traffic itself, so it already knows
// what it is going to send and to whom: the filter is computed from the test's
// own configuration, and every value in it is either an address that `net.isIP`
// has accepted or an integer port. There is no free text anywhere in the
// expression, which is what makes a hand-written filter dangerous.
//
// A filter this module cannot build is not "unfiltered" — it is a refusal. An
// unfiltered capture is exactly what this feature must never be able to become,
// so `buildFilter` returns an error rather than falling back to a wider one.

const net = require('net');
const { URL } = require('url');

// Bounded so the expression stays short and one test can never widen into a
// site-wide capture: a transaction with more distinct endpoints than this is
// not a transaction any more.
const MAX_TARGETS = 8;

const PROTOS = Object.freeze(['tcp', 'udp', 'icmp']);

function isPort(n) { return Number.isInteger(n) && n > 0 && n <= 65535; }

// Every endpoint a test will talk to, as { host, port, proto }, with `host` a
// NAME as configured (resolution happens in the runner, which has DNS).
// Pure: same test in, same list out.
function targetsForTest(test, { resolvers = [] } = {}) {
  const t = test && typeof test === 'object' ? test : {};
  const cfg = t.config && typeof t.config === 'object' ? t.config : {};
  const type = String(t.type || '').toLowerCase();
  const out = [];
  const seen = new Set();

  const add = (host, port, proto) => {
    if (!host || !PROTOS.includes(proto)) return;
    if (proto !== 'icmp' && !isPort(port)) return;
    const key = `${proto}|${host}|${proto === 'icmp' ? '' : port}`;
    if (seen.has(key) || out.length >= MAX_TARGETS) return;
    seen.add(key);
    out.push({ host: String(host), port: proto === 'icmp' ? null : port, proto });
  };

  if (type === 'http') {
    for (const step of Array.isArray(cfg.steps) ? cfg.steps : []) {
      const raw = step && typeof step.url === 'string' ? step.url : '';
      // A url carrying an unsubstituted {{secret:x}} or {{var}} is skipped
      // rather than guessed at: a filter built on a placeholder would capture
      // the wrong host, and capturing the wrong host is the failure mode this
      // whole module exists to prevent.
      if (!raw || raw.includes('{{')) continue;
      let u;
      try { u = new URL(raw); } catch { continue; }
      const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
      add(u.hostname.replace(/^\[|\]$/g, ''), port, 'tcp');
    }
  } else if (type === 'tcp') {
    add(t.target, Number(cfg.port), 'tcp');
  } else if (type === 'dns') {
    // The traffic goes to the RESOLVER, not to the name being looked up. The
    // runner passes the host's configured resolvers in; with none known there
    // is nothing to capture, and that is reported rather than widened.
    for (const r of resolvers) add(r, 53, 'udp');
  } else if (type === 'icmp') {
    add(t.target, null, 'icmp');
  }

  return out;
}

// Builds the pcap-filter expression from RESOLVED targets ({ ip, port, proto }).
// Returns { expression, targets } or { error }.
function buildFilter(targets) {
  const list = Array.isArray(targets) ? targets : [];
  if (!list.length) return { error: 'no capture targets could be derived from this test' };
  if (list.length > MAX_TARGETS) return { error: `too many capture targets (max ${MAX_TARGETS})` };

  const clauses = [];
  const accepted = [];
  for (const raw of list) {
    const t = raw && typeof raw === 'object' ? raw : {};
    const ip = typeof t.ip === 'string' ? t.ip.trim() : '';
    const proto = String(t.proto || '').toLowerCase();
    // net.isIP is the whole address validation. It accepts exactly the literals
    // that are addresses and nothing that could be read as another token, which
    // is stricter than any regex written here would be.
    const family = net.isIP(ip);
    if (!family) return { error: `capture target is not an IP address: ${String(t.ip)}` };
    if (!PROTOS.includes(proto)) return { error: `capture target has an unsupported protocol: ${String(t.proto)}` };

    if (proto === 'icmp') {
      // IPv6 carries ICMP under its own protocol number, and `icmp` does not
      // match it — a v6 target filtered as `icmp` captures nothing at all.
      clauses.push(`(${family === 6 ? 'icmp6' : 'icmp'} and host ${ip})`);
      accepted.push({ ip, port: null, proto });
    } else {
      const port = Number(t.port);
      if (!isPort(port)) return { error: `capture target has an invalid port: ${String(t.port)}` };
      clauses.push(`(host ${ip} and ${proto} port ${port})`);
      accepted.push({ ip, port, proto });
    }
  }

  return { expression: clauses.join(' or '), targets: accepted };
}

// The argv for tcpdump. Built as a list, never a string: there is no shell, so
// there is nothing for a value to escape out of — and the values are already
// only addresses and integers.
//
// -s <snaplen>  headers only (see SNAPLEN below)
// -w -          write the pcap stream to stdout
// -U            packet-buffered, so frames arrive while the test is running
//               rather than in one block when tcpdump exits
// -n            never resolve names: a capture must not itself generate DNS
// -p            no promiscuous mode. The agent captures ITS OWN conversation;
//               putting the NIC into promiscuous mode to do that would collect
//               the segment's traffic as a side effect.
// -c <count>    a hard ceiling in tcpdump itself, so the cap holds even if the
//               agent stops reading
function tcpdumpArgs({ iface, expression, snaplen, maxPackets }) {
  const args = ['-i', String(iface), '-s', String(snaplen), '-w', '-', '-U', '-n', '-p'];
  if (Number.isInteger(maxPackets) && maxPackets > 0) args.push('-c', String(maxPackets));
  args.push(expression);
  return args;
}

module.exports = { targetsForTest, buildFilter, tcpdumpArgs, MAX_TARGETS, PROTOS };
