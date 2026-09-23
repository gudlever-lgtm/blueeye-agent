'use strict';

// Tests for the local LLDP reader (src/lldp.js).
//
// The server has read capabilities.lldp + lldpChassisId for a long time
// (agentReports → topologyChangeService.processReport → lldpNeighborsRepository
// .upsertMany); these pin the agent to that exact shape:
//   [{ localPort, remoteChassisId, remotePort, linkState }]
// and to the one rule that matters most — a host that cannot ASK lldpd omits
// the field instead of sending [], because [] is a snapshot the server diffs
// into "every neighbour removed".

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { collectLldp, parseLldpNeighbours, parseLocalChassisId, MAX_NEIGHBOURS } = require('../src/lldp');

// `lldpctl -f json` from lldpd 1.0.x on a host with two uplinks: eth0 to a
// Cisco access switch that advertises a system name, eth1 to a device that
// does not (so its chassis block is NOT keyed by name). Multiple interfaces
// come back as an array of single-key objects.
const TWO_LINKS = {
  lldp: {
    interface: [
      {
        eth0: {
          via: 'LLDP',
          rid: '1',
          age: '0 day, 02:13:41',
          chassis: {
            'sw-access-3.plant.lan': {
              id: { type: 'mac', value: '00:1B:44:11:3A:B7' },
              descr: 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11',
              'mgmt-ip': '10.14.0.13',
              capability: [
                { type: 'Bridge', enabled: true },
                { type: 'Router', enabled: false },
              ],
            },
          },
          port: {
            id: { type: 'ifname', value: 'Gi1/0/24' },
            descr: 'GigabitEthernet1/0/24',
            ttl: '120',
            'auto-negotiation': { supported: true, enabled: true, current: '1000BaseTFD - Four-pair Category 5 UTP, full duplex mode' },
          },
          vlan: { 'vlan-id': '20', pvid: true, value: 'Kontor' },
        },
      },
      {
        eth1: {
          via: 'LLDP',
          rid: '2',
          age: '0 day, 00:00:41',
          chassis: {
            id: { type: 'local', value: 'PLC-LINE-2' },
            descr: 'SIMATIC S7-1500',
          },
          port: {
            id: { type: 'local', value: 'port-001' },
            ttl: '20',
          },
        },
      },
    ],
  },
};

// One interface: lldpctl collapses the list into a plain object.
const ONE_LINK = {
  lldp: {
    interface: {
      eno1: {
        via: 'LLDP',
        rid: '1',
        chassis: { 'core-sw': { id: { type: 'mac', value: 'aa:bb:cc:00:11:22' } } },
        port: { id: { type: 'mac', value: 'AA:BB:CC:00:11:30' }, descr: 'ge-0/0/12' },
      },
    },
  },
};

const LOCAL_CHASSIS = {
  'local-chassis': {
    chassis: {
      'hmi-01': {
        id: { type: 'mac', value: '52:54:00:AB:CD:EF' },
        descr: 'Debian GNU/Linux 12 (bookworm) Linux 6.1.0-18-amd64',
        'mgmt-ip': ['10.14.0.50', 'fe80::5054:ff:feab:cdef'],
      },
    },
  },
};

test('two links map to the exact shape the server reads', () => {
  const up = (ifname) => (ifname === 'eth0' ? 'up' : 'lowerlayerdown');
  const out = parseLldpNeighbours(TWO_LINKS, { linkStateOf: up });
  assert.deepEqual(out, [
    { localPort: 'eth0', remoteChassisId: '00:1b:44:11:3a:b7', remotePort: 'Gi1/0/24', linkState: 'up' },
    { localPort: 'eth1', remoteChassisId: 'PLC-LINE-2', remotePort: 'port-001', linkState: 'lowerlayerdown' },
  ]);
  // Nothing else leaks into the rows (the server stores what it is given).
  for (const n of out) assert.deepEqual(Object.keys(n).sort(), ['linkState', 'localPort', 'remoteChassisId', 'remotePort']);
});

test('a single link (object, not array) parses the same way; a MAC is lowercased', () => {
  const out = parseLldpNeighbours(JSON.stringify(ONE_LINK));
  assert.deepEqual(out, [{ localPort: 'eno1', remoteChassisId: 'aa:bb:cc:00:11:22', remotePort: 'aa:bb:cc:00:11:30', linkState: null }]);
});

test('the json0 layout (everything wrapped in arrays) is read too', () => {
  const json0 = {
    lldp: [{
      interface: [{
        name: 'eth0', via: 'LLDP',
        chassis: [{ id: [{ type: 'mac', value: '00:11:22:33:44:55' }], name: [{ value: 'sw-1' }] }],
        port: [{ id: [{ type: 'ifname', value: 'ge-0/0/1' }] }],
      }],
    }],
  };
  assert.deepEqual(parseLldpNeighbours(json0), [
    { localPort: 'eth0', remoteChassisId: '00:11:22:33:44:55', remotePort: 'ge-0/0/1', linkState: null },
  ]);
});

test('no neighbours, garbage and a neighbour without a chassis id', () => {
  assert.deepEqual(parseLldpNeighbours({ lldp: {} }), []);
  assert.deepEqual(parseLldpNeighbours('not json'), []);
  assert.deepEqual(parseLldpNeighbours(null), []);
  const noId = { lldp: { interface: { eth0: { chassis: { descr: 'x' }, port: { id: { type: 'ifname', value: 'p1' } } } } } };
  assert.deepEqual(parseLldpNeighbours(noId), [], 'the server requires a remote chassis id');
});

test('fields are bounded to the column width and the list is capped', () => {
  const long = 'x'.repeat(400);
  const many = { lldp: { interface: [] } };
  for (let i = 0; i < MAX_NEIGHBOURS + 20; i += 1) {
    many.lldp.interface.push({ [`eth${i}`]: { chassis: { id: { type: 'local', value: `${long}${i}` } }, port: { id: { type: 'local', value: long } } } });
  }
  const out = parseLldpNeighbours(many);
  assert.equal(out.length, MAX_NEIGHBOURS);
  assert.equal(out[0].remoteChassisId.length, 190);
  assert.equal(out[0].remotePort.length, 190);
});

test('the local chassis id comes from `lldpcli show chassis`', () => {
  assert.equal(parseLocalChassisId(LOCAL_CHASSIS), '52:54:00:ab:cd:ef');
  assert.equal(parseLocalChassisId('{}'), null);
  assert.equal(parseLocalChassisId('nope'), null);
});

// ------------------------------------------------------------ collectLldp
function fakeRun(table) {
  const calls = [];
  const run = async (bin, args) => {
    calls.push([bin, ...args]);
    const r = table[bin];
    if (typeof r === 'function') return r();
    return r || { err: Object.assign(new Error(`spawn ${bin} ENOENT`), { code: 'ENOENT' }), stdout: '', stderr: '' };
  };
  return { run, calls };
}

test('lldpd answering: neighbours + own chassis id, via lldpctl -f json', async () => {
  const { run, calls } = fakeRun({
    lldpctl: { err: null, stdout: JSON.stringify(TWO_LINKS), stderr: '' },
    lldpcli: { err: null, stdout: JSON.stringify(LOCAL_CHASSIS), stderr: '' },
  });
  const r = await collectLldp({ run, linkStateOf: () => 'up' });
  assert.equal(r.neighbours.length, 2);
  assert.equal(r.chassisId, '52:54:00:ab:cd:ef');
  assert.equal(r.unavailable, undefined);
  assert.deepEqual(calls[0], ['lldpctl', '-f', 'json']);
  assert.deepEqual(calls[1], ['lldpcli', '-f', 'json', 'show', 'chassis']);
});

test('lldpd running with nobody on the wire is [] — a real, sendable answer', async () => {
  const { run } = fakeRun({ lldpctl: { err: null, stdout: '{"lldp": {}}', stderr: '' } });
  const r = await collectLldp({ run, linkStateOf: () => null });
  assert.deepEqual(r.neighbours, []);
  assert.equal(r.chassisId, null, 'no lldpcli → no chassis id, neighbours still reported');
});

test('lldpctl not installed → unavailable with a reason, no neighbours', async () => {
  const { run } = fakeRun({});
  const r = await collectLldp({ run });
  assert.equal(r.neighbours, undefined);
  assert.match(r.unavailable, /lldpd is not installed/);
});

test('lldpd installed but not running → unavailable, not []', async () => {
  const { run } = fakeRun({
    lldpctl: {
      err: Object.assign(new Error('Command failed: lldpctl -f json'), { code: 1 }),
      stdout: '',
      stderr: '[lldpctl] unable to connect to socket /run/lldpd.socket\n',
    },
  });
  const r = await collectLldp({ run });
  assert.equal(r.neighbours, undefined);
  assert.match(r.unavailable, /not running/);
});

test('a runner that throws or times out never throws out of collectLldp', async () => {
  assert.match((await collectLldp({ run: async () => { throw new Error('boom'); } })).unavailable, /boom/);
  const killed = await collectLldp({ run: async () => ({ err: Object.assign(new Error('t'), { killed: true }), stdout: '', stderr: '' }) });
  assert.match(killed.unavailable, /timed out/);
});
