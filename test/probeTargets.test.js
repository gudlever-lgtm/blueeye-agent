'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseConfiguredTargets, gatewayFromProcRoute, defaultRouteInterface, nameserversFromResolv, resolveProbeTargets } = require('../src/probes/targets');

test('parseConfiguredTargets parses the common forms', () => {
  assert.deepEqual(
    parseConfiguredTargets('ping:1.1.1.1, tcp:example.com:443, dns:example.com, 8.8.8.8, host:8443'),
    [
      { type: 'ping', host: '1.1.1.1' },
      { type: 'tcp', host: 'example.com', port: 443 },
      { type: 'dns', host: 'example.com' },
      { type: 'ping', host: '8.8.8.8' },
      { type: 'tcp', host: 'host', port: 8443 },
    ]
  );
});

test('parseConfiguredTargets keeps IPv6 literals intact (bare, typed, bracketed, trailing port)', () => {
  assert.deepEqual(
    parseConfiguredTargets('2606:4700:4700::1111, ping:2606:4700::1111, [2001:db8::1], [2001:db8::1]:443, tcp:[2001:db8::2]:22, tcp:2606:4700:4700::1111:443, dns:2001:db8::53'),
    [
      { type: 'ping', host: '2606:4700:4700::1111' },
      { type: 'ping', host: '2606:4700::1111' },
      { type: 'ping', host: '2001:db8::1' },
      { type: 'tcp', host: '2001:db8::1', port: 443 },
      { type: 'tcp', host: '2001:db8::2', port: 22 },
      { type: 'tcp', host: '2606:4700:4700::1111', port: 443 },
      { type: 'dns', host: '2001:db8::53' },
    ]
  );
  // objects with IPv6 hosts survive the normalizeOne round-trip
  assert.deepEqual(parseConfiguredTargets([{ type: 'tcp', host: '2001:db8::9', port: 8443 }]), [
    { type: 'tcp', host: '2001:db8::9', port: 8443 },
  ]);
});

test('parseConfiguredTargets accepts an array of strings/objects and drops invalid tcp', () => {
  assert.deepEqual(parseConfiguredTargets(['ping:1.1.1.1', { type: 'tcp', host: 'h', port: 22 }]), [
    { type: 'ping', host: '1.1.1.1' }, { type: 'tcp', host: 'h', port: 22 },
  ]);
  assert.deepEqual(parseConfiguredTargets('tcp:host'), []); // tcp needs a port
  assert.deepEqual(parseConfiguredTargets(''), []);
  assert.deepEqual(parseConfiguredTargets(undefined), []);
});

test('gatewayFromProcRoute decodes the default-route gateway (little-endian hex)', () => {
  const route = [
    'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask',
    'eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF', // subnet route — skipped
    'eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000', // default route
  ].join('\n');
  assert.equal(gatewayFromProcRoute(route), '192.168.0.1');
  assert.equal(gatewayFromProcRoute('Iface\tDestination\tGateway\n'), null);
});

test('defaultRouteInterface returns the NIC of the default route (Iface column)', () => {
  const route = [
    'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask',
    'ens3\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF', // subnet route — skipped
    'ens3\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000', // default route
  ].join('\n');
  assert.equal(defaultRouteInterface(route), 'ens3');
  assert.equal(defaultRouteInterface('Iface\tDestination\tGateway\n'), null); // header only
  assert.equal(defaultRouteInterface(''), null);
});

test('nameserversFromResolv extracts non-loopback nameservers, de-duplicated', () => {
  const resolv = 'nameserver 192.168.0.1\n# comment\nnameserver 127.0.0.53\nnameserver 9.9.9.9\nnameserver 192.168.0.1';
  assert.deepEqual(nameserversFromResolv(resolv), ['192.168.0.1', '9.9.9.9']);
});

test('resolveProbeTargets combines gateway + DNS + configured and de-duplicates', async () => {
  const specs = await resolveProbeTargets({
    platform: 'linux',
    readRoute: async () => 'Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0100A8C0\t0003',
    readResolv: async () => 'nameserver 192.168.0.1\nnameserver 9.9.9.9', // 192.168.0.1 dupes the gateway
    configured: [{ type: 'ping', host: '1.1.1.1' }],
    count: 2,
  });
  const hosts = specs.map((s) => s.host);
  assert.ok(hosts.includes('192.168.0.1') && hosts.includes('9.9.9.9') && hosts.includes('1.1.1.1'));
  assert.equal(specs.filter((s) => s.host === '192.168.0.1').length, 1); // gateway+dns deduped
  assert.equal(specs.find((s) => s.host === '192.168.0.1').count, 2);
});

test('resolveProbeTargets skips gateway auto-discovery off Linux', async () => {
  const specs = await resolveProbeTargets({ platform: 'darwin', dns: false, configured: [], readRoute: async () => { throw new Error('should not be read'); } });
  assert.deepEqual(specs, []);
});
