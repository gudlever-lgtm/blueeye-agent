# Real SNMP trap datagrams from Net-SNMP `snmptrap`

Each `.bin` is one raw UDP payload exactly as Net-SNMP's `snmptrap` sent it,
captured by a plain Node `dgram` socket on 127.0.0.1 that wrote each message to
a file. Used by [`test/trapsRealCapture.test.js`](../../trapsRealCapture.test.js).

Captured 2026-09-24 with **NET-SNMP 5.9.4.pre2** (Ubuntu 24.04 package `snmp`),
`MIBS=""` so every OID below is numeric and nothing depended on MIB files.
`192.0.2.10` (RFC 5737) is the v1 agent-addr; `1.3.6.1.4.1.9.1.1208` (a Cisco
sysObjectID) is the v1 enterprise for the generic traps. The v1 timestamp is the
sending host's uptime, so it differs per file.

| File | Command (target `127.0.0.1:16162`) |
| --- | --- |
| `001-v1-linkdown-admin-down.bin` | `snmptrap -v1 -c public $T 1.3.6.1.4.1.9.1.1208 192.0.2.10 2 0 '' 1.3.6.1.2.1.2.2.1.1.3 i 3 1.3.6.1.2.1.2.2.1.7.3 i 2 1.3.6.1.2.1.2.2.1.8.3 i 2` |
| `002-v1-linkup.bin` | `snmptrap -v1 -c public $T 1.3.6.1.4.1.9.1.1208 192.0.2.10 3 0 '' 1.3.6.1.2.1.2.2.1.1.3 i 3 1.3.6.1.2.1.2.2.1.7.3 i 1 1.3.6.1.2.1.2.2.1.8.3 i 1` |
| `003-v1-coldstart.bin` | `snmptrap -v1 -c public $T 1.3.6.1.4.1.9.1.1208 192.0.2.10 0 0 ''` |
| `004-v1-cisco-config-man-event.bin` | `snmptrap -v1 -c public $T 1.3.6.1.4.1.9.9.43.2 192.0.2.10 6 1 '' 1.3.6.1.4.1.9.9.43.1.1.6.1.3.42 i 1 1.3.6.1.4.1.9.9.43.1.1.6.1.4.42 i 3 1.3.6.1.4.1.9.9.43.1.1.6.1.5.42 i 3` |
| `005-v2c-linkdown-oper-down.bin` | `snmptrap -v2c -c public $T 123456 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.10103 i 10103 1.3.6.1.2.1.2.2.1.7.10103 i 1 1.3.6.1.2.1.2.2.1.8.10103 i 2 1.3.6.1.2.1.2.2.1.2.10103 s "GigabitEthernet1/0/3"` |
| `006-v2c-linkdown-admin-down.bin` | `snmptrap -v2c -c public $T 123460 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.10104 i 10104 1.3.6.1.2.1.2.2.1.7.10104 i 2 1.3.6.1.2.1.2.2.1.8.10104 i 2` |
| `007-v2c-linkup.bin` | `snmptrap -v2c -c public $T 123470 1.3.6.1.6.3.1.1.5.4 1.3.6.1.2.1.2.2.1.1.10103 i 10103 1.3.6.1.2.1.2.2.1.7.10103 i 1 1.3.6.1.2.1.2.2.1.8.10103 i 1` |
| `008-v2c-coldstart.bin` | `snmptrap -v2c -c public $T 42 1.3.6.1.6.3.1.1.5.1` |
| `009-v2c-cisco-config-man-event.bin` | `snmptrap -v2c -c public $T 987654 1.3.6.1.4.1.9.9.43.2.0.1 1.3.6.1.4.1.9.9.43.1.1.6.1.3.43 i 1 1.3.6.1.4.1.9.9.43.1.1.6.1.4.43 i 3 1.3.6.1.4.1.9.9.43.1.1.6.1.5.43 i 3` |
| `010-v2c-coldstart-other-community.bin` | `snmptrap -v2c -c notthesame $T 42 1.3.6.1.6.3.1.1.5.1` |
| `011-v3-noauth-coldstart.bin` | `snmptrap -v3 -e 0x8000000001020304 -u blueeye -l noAuthNoPriv $T 42 1.3.6.1.6.3.1.1.5.1` |

The OIDs: `1.3.6.1.6.3.1.1.5.{1,3,4}` coldStart/linkDown/linkUp (SNMPv2-MIB);
`1.3.6.1.2.1.2.2.1.{1,2,7,8}` ifIndex/ifDescr/ifAdminStatus/ifOperStatus
(IF-MIB, 1 = up, 2 = down); `1.3.6.1.4.1.9.9.43.2.0.1` ciscoConfigManEvent with
ccmHistoryEventCommandSource (`…43.1.1.6.1.3`, 1 = commandLine),
ccmHistoryEventConfigSource / ConfigDestination (`…43.1.1.6.1.4` / `.5`, 3 =
running) from CISCO-CONFIG-MAN-MIB. A v1 trap with generic 6 / specific 1 under
enterprise `1.3.6.1.4.1.9.9.43.2` is the same notification by RFC 3584 §3.1
(`enterprise.0.specific`).
