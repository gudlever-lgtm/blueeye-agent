'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseConfiguredTargets, gatewayFromProcRoute, nameserversFromResolv, resolveProbeTargets } = require('../src/probes/targets');

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
