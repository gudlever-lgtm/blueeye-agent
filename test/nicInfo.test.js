'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { collectNicInfo, parseEthtoolInfo } = require('../src/nicInfo');

const ETHTOOL_ETH0 = `driver: e1000e
version: 3.2.6-k
firmware-version: 0.13-4
expansion-rom-version:
bus-info: 0000:00:1f.6
supports-statistics: yes`;

const ETHTOOL_WLAN0 = `driver: iwlwifi
version: 6.6.0
firmware-version: 83.20428e91.0 wl0_3.5.6.0
bus-info: 0000:00:14.3`;

test('parseEthtoolInfo extracts driver, version, firmware and bus-info', () => {
  const info = parseEthtoolInfo(ETHTOOL_ETH0);
  assert.equal(info.driver, 'e1000e');
  assert.equal(info.driverVersion, '3.2.6-k');
  assert.equal(info.firmwareVersion, '0.13-4');
  assert.equal(info.busInfo, '0000:00:1f.6');
});

test('parseEthtoolInfo leaves missing/empty fields null', () => {
  const info = parseEthtoolInfo('driver: bridge\nversion: 2.3\nfirmware-version:\nbus-info:');
  assert.equal(info.driver, 'bridge');
  assert.equal(info.driverVersion, '2.3');
  assert.equal(info.firmwareVersion, null);
  assert.equal(info.busInfo, null);
});

test('parseEthtoolInfo treats N/A-style placeholders as absent', () => {
  const info = parseEthtoolInfo('driver: bridge\nversion: N/A\nfirmware-version: N/A\nbus-info: N/A');
  assert.equal(info.driver, 'bridge'); // a real name is kept
  assert.equal(info.driverVersion, null);
  assert.equal(info.firmwareVersion, null);
  assert.equal(info.busInfo, null);
});

test('collectNicInfo drops a software bridge whose firmware is only "N/A"', async () => {
  const nics = await collectNicInfo({
    platform: 'linux',
    listIfaces: async () => ['eth0', 'br0'],
    runEthtool: async (iface) => (iface === 'eth0' ? ETHTOOL_ETH0 : 'driver: bridge\nfirmware-version: N/A\nbus-info: N/A'),
    readSysfsId: async () => null,
  });
  assert.deepEqual(nics.map((n) => n.iface), ['eth0']);
});

test('collectNicInfo returns one entry per physical interface', async () => {
  const byIface = { eth0: ETHTOOL_ETH0, wlan0: ETHTOOL_WLAN0 };
  const nics = await collectNicInfo({
    platform: 'linux',
    listIfaces: async () => ['eth0', 'wlan0'],
    runEthtool: async (iface) => byIface[iface] || null,
    readSysfsId: async (iface) => (iface === 'eth0' ? '8086:15bc' : null),
  });
  assert.equal(nics.length, 2);
  const eth0 = nics.find((n) => n.iface === 'eth0');
  assert.equal(eth0.driver, 'e1000e');
  assert.equal(eth0.firmwareVersion, '0.13-4');
  assert.equal(eth0.pciId, '8086:15bc');
  const wlan0 = nics.find((n) => n.iface === 'wlan0');
  assert.equal(wlan0.driver, 'iwlwifi');
  assert.equal(wlan0.firmwareVersion, '83.20428e91.0 wl0_3.5.6.0');
});

test('collectNicInfo drops pure-virtual interfaces (no bus, firmware or PCI id)', async () => {
  const nics = await collectNicInfo({
    platform: 'linux',
    listIfaces: async () => ['eth0', 'docker0', 'veth123'],
    runEthtool: async (iface) => (iface === 'eth0' ? ETHTOOL_ETH0 : 'driver: bridge\nbus-info:'),
    readSysfsId: async () => null,
  });
  assert.deepEqual(nics.map((n) => n.iface), ['eth0']);
});

test('collectNicInfo keeps a NIC known only from sysfs when ethtool is unavailable', async () => {
  const nics = await collectNicInfo({
    platform: 'linux',
    listIfaces: async () => ['eth0'],
    runEthtool: async () => null, // ethtool missing
    readSysfsId: async () => '10ec:8168',
  });
  assert.equal(nics.length, 1);
  assert.equal(nics[0].pciId, '10ec:8168');
  assert.equal(nics[0].firmwareVersion, null);
});

test('collectNicInfo returns [] on non-Linux platforms', async () => {
  const nics = await collectNicInfo({ platform: 'darwin', listIfaces: async () => ['en0'] });
  assert.deepEqual(nics, []);
});

test('collectNicInfo is resilient to a listIfaces failure', async () => {
  const nics = await collectNicInfo({ platform: 'linux', listIfaces: async () => { throw new Error('boom'); } });
  assert.deepEqual(nics, []);
});
