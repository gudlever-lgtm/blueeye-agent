'use strict';

const { parseCidr, totalAddresses, expand, inScope } = require('./cidr');
const { tcpConnect, reverseDns, icmpUnsupported } = require('./probes');
const { createRateLimiter } = require('./rateLimiter');

// Scoped active-discovery scanner. Given a list of admin-configured CIDRs, it
// probes ONLY addresses inside that scope — ICMP echo (injectable; unsupported
// by default), TCP connect on a small port list, reverse DNS — and returns the
// live hosts as discovery candidates. Rate-limited. Never expands scope.
//
// Refuses (throws {code}) when scope is empty/invalid or exceeds the address cap
// — checked BEFORE any address is enumerated or probed.

const DEFAULT_PORTS = [22, 80, 161, 443, 3389];

class DiscoveryScopeError extends Error {
  constructor(code, message) { super(message); this.code = code; this.name = 'DiscoveryScopeError'; }
}

function validateScope({ cidrs, addressCap }) {
  const list = Array.isArray(cidrs) ? cidrs.filter((c) => String(c).trim()) : [];
  if (list.length === 0) throw new DiscoveryScopeError('scope_unconfigured', 'Discovery scope is not configured');
  const { count, cidrs: parsed, invalid } = totalAddresses(list);
  if (invalid.length) throw new DiscoveryScopeError('scope_invalid', `Invalid CIDR(s): ${invalid.join(', ')}`);
  if (count > addressCap) throw new DiscoveryScopeError('scope_too_large', `Scope covers ${count} addresses, exceeds cap ${addressCap}`);
  return { parsed, count };
}

function createScanner({
  tcpProbe = tcpConnect,
  icmpProbe = icmpUnsupported,
  dnsReverse = reverseDns,
  ports = DEFAULT_PORTS,
  tcpTimeoutMs = 1000,
} = {}) {
  // Scan the configured scope. `rateLimiter` may be injected (tests); otherwise
  // one is built from `ratePerSec`. Returns { candidates, probed, addresses }.
  async function scan({ cidrs, addressCap = 65536, ratePerSec = 50, rateLimiter = null, portList = ports } = {}) {
    const { parsed, count } = validateScope({ cidrs, addressCap });
    const limiter = rateLimiter || createRateLimiter({ ratePerSec });
    const probePorts = Array.isArray(portList) && portList.length ? portList : DEFAULT_PORTS;

    const candidates = [];
    const probed = [];
    for (const p of parsed) {
      for (const ip of expand(p)) {
        // Hard scope guard — a target outside the configured CIDRs is never probed.
        if (!inScope(ip, parsed)) continue;

        await limiter.acquire(); // eslint-disable-line no-await-in-loop
        probed.push(ip);
        const icmp = await icmpProbe(ip); // eslint-disable-line no-await-in-loop

        const openPorts = [];
        for (const port of probePorts) {
          await limiter.acquire(); // eslint-disable-line no-await-in-loop
          const open = await tcpProbe(ip, port, { timeoutMs: tcpTimeoutMs }); // eslint-disable-line no-await-in-loop
          if (open) openPorts.push(port);
        }

        const alive = icmp === true || openPorts.length > 0;
        if (!alive) continue;

        await limiter.acquire(); // eslint-disable-line no-await-in-loop
        const hostname = await dnsReverse(ip); // eslint-disable-line no-await-in-loop
        candidates.push({ ip, hostname: hostname || null, openPorts, icmp: icmp === true });
      }
    }
    return { candidates, probed, addresses: count };
  }

  return { scan };
}

module.exports = { createScanner, validateScope, DiscoveryScopeError, DEFAULT_PORTS };
