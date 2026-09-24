# snmpsim recordings of real switches

`.snmprec` walks of two real switches from
[lextudio/snmpsim-data](https://github.com/lextudio/snmpsim-data) at commit
`ba7bc06baea3dce8864a775b6d28a3dd270f51ba`, **BSD 2-Clause, © 2019 Ilya Etingof**
— the licence is reproduced in [`LICENSE-snmpsim-data.txt`](LICENSE-snmpsim-data.txt)
as its terms require.

| File | Source in snmpsim-data | Device |
| --- | --- | --- |
| `hpe-procurve-516733-b21.snmprec` | `snmpsim_data/data/network/switch/hpe-procurve-516733-b21.snmprec.bz2` | HPE ProCurve 6120XG blade switch, Z.14.31 — 42 ifIndexes, Q-BRIDGE FDB (285 rows), LLDP, CDP, 8 VLAN names, EtherLike |
| `cisco-c3750.snmprec` | `snmpsim_data/data/network/switch/cisco-c3750.snmprec.bz2` | Cisco Catalyst 3750 — 19 ifIndexes, BRIDGE-MIB dot1d FDB whose bridge ports (1..12) are NOT the ifIndexes (10101..), 125 CDP neighbours, HC counters above 2^47 |

**Trimmed, not edited.** Each file keeps only the lines whose OID is one of the
columns/scalars in the agent's `src/snmp/oids.js` (except IP-MIB and
ENTITY-MIB), i.e. exactly what `snmpTopology.js` and `snmp/counters.js` read;
every kept line is byte-identical to the original. (A 2 MB walk becomes
100 kB.)

The 3750 file also carries the recording's CISCO-VTP-MIB `vtpVlanState` and
`vtpVlanName` rows (`1.3.6.1.4.1.9.9.46.1.3.1.1.{2,4}`, 556 lines, appended
2026-09-24 when the agent started reading them) — the VLAN names IOS publishes
instead of Q-BRIDGE, and the VLAN list the per-VLAN forwarding walk iterates.
The recording holds the DEFAULT bridge instance only (VLAN 1's table on IOS);
it has no `community@vlan` data, so `test/snmpCiscoVlans.test.js` serves the
other VLANs' tables from a fake session keyed by community. snmpsim 1.2.2
does serve community indexing: a data file named `<community>@<vlan>.snmprec`
answers the community `<community>@<vlan>`, which is how the per-VLAN walk was
checked end to end with the real `net-snmp` module.

## Used by

- `test-support/snmprec.js` — turns a recording into the varbinds net-snmp
  returns (Integer/Counter32/Gauge32/TimeTicks → number, OctetString/Counter64 →
  Buffer with BER's sign pad, OID/IpAddress → string) behind a net-snmp-shaped
  `get`/`subtree` session.
- `test/snmpRealWalks.test.js` — runs `defaultReadTables` → `buildTopology` and
  `defaultReadCounters` over them.

## Checked against a real SNMP stack (2026-09-24)

The same two files served by **snmpsim 1.2.2** (`pip install snmpsim pysmi`;
`snmpsim-command-responder --data-dir=<dir> --agent-udpv4-endpoint=127.0.0.1:16100`,
community = file name) and walked by the agent's readers with the real
**net-snmp 3.29.1** module give identical varbinds and identical
topology/counter output. That comparison is the opt-in test in
`test/snmpRealWalks.test.js`: set `BLUEEYE_SNMPSIM_ENDPOINT=127.0.0.1:16100`.

It is how the Counter64 bug was found: net-snmp returns a counter ≥ 2^47 as a
7-byte Buffer (`00 ea 2f 0b 66 84 6d`), and `toNumber` read only the first six
bytes — the Catalyst's Gi1/0/9 input octets came out 1 005 811 623 556 instead
of 257 487 775 630 445 (256× low). Fixed in `src/snmp/session.js`.

## Server payload fixtures

blueeye-server `test/fixtures/snmp-real/*.json` are these recordings run
through `pollSnmpTopology` / `pollSnmpCounters`. To regenerate after an agent
payload change (from the agent repo root):

```js
const { loadSnmprec, createSnmprecSession, createSnmprecModule } = require('./test-support/snmprec');
const { defaultReadTables, pollSnmpTopology } = require('./src/snmpTopology');
const { defaultReadCounters, pollSnmpCounters } = require('./src/snmp/counters');
// for f of ['hpe-procurve-516733-b21', 'cisco-c3750']:
const vbs = loadSnmprec(`test/fixtures/snmprec/${f}.snmprec`);
const device = { deviceId: 1, host: '192.0.2.50', community: 'public', version: '2c', collect: ['if', 'fdb', 'lldp', 'vlan', 'cdp'] };
const topo = await pollSnmpTopology({ device, readTables: (d, o) => defaultReadTables(d, { ...o, session: createSnmprecSession(vbs) }) });
const ctr = await pollSnmpCounters({ device, readCounters: (d) => defaultReadCounters(d, { snmp: createSnmprecModule(vbs) }), now: () => new Date('2026-09-24T02:00:00.000Z') });
// write { devices: [topo], errors: [] } and { devices: [ctr], errors: [] }
```
