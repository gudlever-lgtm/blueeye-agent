'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { createEvidenceCollector, isAllowed, READ_ONLY_ITEMS } = require('../src/evidenceCollector');

test('the read-only allowlist is exactly the evidence set', () => {
  assert.deepEqual([...READ_ONLY_ITEMS].sort(), ['agent.state', 'arp.table', 'iface.counters', 'snmp.reads']);
  assert.equal(isAllowed('agent.state'), true);
  assert.equal(isAllowed('reboot'), false);
  assert.equal(isAllowed('iface.set'), false);
});

test('a non-allowlisted (write-class) item is REFUSED without invoking any collector', async () => {
  let called = false;
  const collector = createEvidenceCollector({ collectors: { reboot: async () => { called = true; return 'done'; } } });
  const [item] = await collector.collect(['reboot']);
  assert.equal(item.status, 'refused');
  assert.match(item.payload, /read-only evidence allowlist/);
  assert.equal(called, false, 'the collector for a refused item is never called');
});

test('allowlisted items are collected with their payload; partial results are valid', async () => {
  const collector = createEvidenceCollector({
    collectors: {
      'agent.state': async () => 'connected: yes',
      'iface.counters': async () => { throw new Error('no /proc'); }, // fails → timeout status
      // arp.table has no collector → placeholder ok
    },
  });
  const items = await collector.collect(['agent.state', 'iface.counters', 'arp.table', 'reboot']);
  const byName = Object.fromEntries(items.map((i) => [i.name, i]));
  assert.equal(byName['agent.state'].status, 'ok');
  assert.match(byName['agent.state'].payload, /connected: yes/);
  assert.equal(byName['iface.counters'].status, 'timeout'); // collector threw
  assert.equal(byName['arp.table'].status, 'ok');            // no collector → placeholder
  assert.equal(byName.reboot.status, 'refused');             // write-class refused
});

test('empty item list collects the full read-only set', async () => {
  const collector = createEvidenceCollector({ collectors: {} });
  const items = await collector.collect();
  assert.deepEqual(items.map((i) => i.name).sort(), [...READ_ONLY_ITEMS].sort());
  assert.ok(items.every((i) => i.status === 'ok')); // no collectors → placeholders, still read-only
});
