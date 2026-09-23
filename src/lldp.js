'use strict';

const { execFile } = require('child_process');
const fs = require('fs');

// Reads this host's OWN LLDP neighbours from lldpd, so the server's topology
// (lldp_neighbors + topology-change detection) learns which switch port this
// machine is plugged into — without anyone configuring SNMP on that switch.
//
// The server has consumed `capabilities.lldp` + `capabilities.lldpChassisId`
// for a long time (POST /agents/me/capabilities → topologyChangeService, then
// lldpNeighborsRepository.upsertMany); no agent ever sent it. The shape is the
// one those two read, field for field:
//
//   lldp:          [{ localPort, remoteChassisId, remotePort, linkState }]
//   lldpChassisId: this host's own chassis id, or absent
//
// OPTIONAL, like net-snmp: when `lldpctl` is not installed, or lldpd is not
// running, the result says so and the runtime reports it under
// `capabilities.unavailable.lldp` — the field is then OMITTED, never sent as
// []. That distinction is the whole point of the contract: the server diffs
// each report against the previous snapshot, and an empty list means "every
// neighbour has gone", which it would faithfully record as N removals.
//
// Metadata only: chassis/port identifiers the switch already advertises to
// everything on the link. Never throws.

const EXEC_TIMEOUT_MS = 5000;
// A host has a handful of links; a hub or a mis-bridged segment can show
// dozens of neighbours on one. Bounded so one report can't bloat the
// capabilities blob (the server caps the whole object at 64 KiB).
const MAX_NEIGHBOURS = 64;
// lldp_neighbors.{local_port,remote_chassis_id,remote_port} are VARCHAR(190).
const MAX_FIELD = 190;

const clip = (v) => {
  if (v == null) return null;
  const s = String(v).trim();
  return s ? s.slice(0, MAX_FIELD) : null;
};

// lldpctl's JSON collapses a one-element list into a plain object and keeps a
// longer one as an array, so every level has to accept both. `json0` (the
// "stable" format) wraps every value in [{ value }]; unwrap that too.
const asList = (v) => (Array.isArray(v) ? v : (v && typeof v === 'object' ? [v] : []));
const one = (v) => (Array.isArray(v) ? v[0] : v);
function scalar(v) {
  const x = one(v);
  if (x && typeof x === 'object' && 'value' in x) return x.value;
  return x;
}

// An `{ id: { type, value } }` record → its value; a MAC is lowercased so the
// same switch reads the same whether it came from here or from an SNMP walk.
function idOf(rec) {
  const id = one(rec && rec.id);
  if (id == null) return null;
  if (typeof id !== 'object') return clip(id);
  const type = String(scalar(id.type) || '').toLowerCase();
  const value = clip(scalar(id.value));
  return value && type === 'mac' ? value.toLowerCase() : value;
}

// A chassis block is either the record itself ({ id, descr, … }, when the
// neighbour advertises no system name) or keyed by that name
// ({ "sw-core-1": { id, … } }). json0 has the name as a field instead.
function unwrapChassis(chassis) {
  const c = one(chassis);
  if (!c || typeof c !== 'object') return { name: null, rec: null };
  if ('id' in c) return { name: clip(scalar(c.name)), rec: c };
  const keys = Object.keys(c);
  if (keys.length === 1 && c[keys[0]] && typeof c[keys[0]] === 'object') {
    return { name: clip(keys[0]), rec: c[keys[0]] };
  }
  return { name: null, rec: null };
}

// Every { ifname, record } pair under lldp.interface. Classic JSON keys each
// record by the local interface name; json0 carries it as `name`.
function interfaceEntries(doc) {
  const root = one(doc && doc.lldp);
  const out = [];
  for (const entry of asList(root && root.interface)) {
    if (!entry || typeof entry !== 'object') continue;
    if ('name' in entry && ('chassis' in entry || 'port' in entry)) {
      out.push({ ifname: clip(scalar(entry.name)), rec: entry });
      continue;
    }
    for (const [ifname, rec] of Object.entries(entry)) {
      for (const r of asList(rec)) out.push({ ifname: clip(ifname), rec: r });
    }
  }
  return out;
}

// Pure: `lldpctl -f json` output → [{ localPort, remoteChassisId, remotePort, linkState }].
// `linkStateOf(ifname)` is optional; without it linkState is null, which the
// server treats as "not reported" rather than as a state.
function parseLldpNeighbours(json, { linkStateOf = null } = {}) {
  let doc = json;
  if (typeof json === 'string') {
    try { doc = JSON.parse(json); } catch { return []; }
  }
  const out = [];
  const seen = new Set();
  for (const { ifname, rec } of interfaceEntries(doc)) {
    if (out.length >= MAX_NEIGHBOURS) break;
    const { rec: chassis } = unwrapChassis(rec && rec.chassis);
    const remoteChassisId = idOf(chassis);
    // The server requires a remote chassis id; without one the row is noise.
    if (!remoteChassisId) continue;
    const remotePort = idOf(one(rec.port));
    const key = `${ifname}\0${remoteChassisId}\0${remotePort}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let linkState = null;
    if (typeof linkStateOf === 'function' && ifname) {
      try { linkState = clip(linkStateOf(ifname)); } catch { linkState = null; }
    }
    out.push({ localPort: ifname, remoteChassisId, remotePort, linkState });
  }
  return out;
}

// Pure: `lldpcli -f json show chassis` output → this host's own chassis id.
function parseLocalChassisId(json) {
  let doc = json;
  if (typeof json === 'string') {
    try { doc = JSON.parse(json); } catch { return null; }
  }
  const local = one(doc && doc['local-chassis']);
  const { rec } = unwrapChassis(local && local.chassis);
  return idOf(rec);
}

function defaultRun(bin, args) {
  return new Promise((resolve) => {
    try {
      execFile(bin, args, { timeout: EXEC_TIMEOUT_MS, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        resolve({ err: err || null, stdout: String(stdout || ''), stderr: String(stderr || '') });
      });
    } catch (err) {
      resolve({ err, stdout: '', stderr: '' });
    }
  });
}

// Linux operstate ('up' / 'down' / 'lowerlayerdown' …), or null anywhere else.
function defaultLinkStateOf(ifname) {
  if (!/^[A-Za-z0-9._@:-]{1,32}$/.test(ifname)) return null;
  try {
    const s = fs.readFileSync(`/sys/class/net/${ifname}/operstate`, 'utf8').trim().toLowerCase();
    return s && s !== 'unknown' ? s : null;
  } catch {
    return null;
  }
}

// Why the neighbour table could not be read, in words for the dashboard.
function unavailableReason(run) {
  const { err } = run;
  if (err && err.code === 'ENOENT') return 'lldpd is not installed (lldpctl not found) — install lldpd to report this host\'s switch port';
  if (err && err.killed) return 'lldpctl timed out';
  const text = `${run.stderr}\n${(err && err.message) || ''}`.toLowerCase();
  if (/unable to connect|connection refused|no such file|cannot connect|lldpd.*running/.test(text)) {
    return 'lldpd is installed but not running';
  }
  if (/permission denied|not permitted/.test(text)) return 'no permission to query lldpd';
  return `lldpctl failed: ${String((err && err.message) || run.stderr || 'unknown error').split('\n')[0].slice(0, 120)}`;
}

// Resolves { neighbours, chassisId } when lldpd answered (neighbours may be
// [] — "lldpd runs and sees nobody" is a real answer), or { unavailable } when
// it could not be asked. Never throws.
async function collectLldp({ run = defaultRun, linkStateOf = defaultLinkStateOf } = {}) {
  try {
    const r = await run('lldpctl', ['-f', 'json']);
    let doc = null;
    try { doc = JSON.parse(r.stdout); } catch { doc = null; }
    // lldpctl can exit non-zero with nothing useful; it can also print a
    // valid document and complain on stderr. The document decides.
    if (!doc || typeof doc !== 'object') return { unavailable: unavailableReason(r) };
    const neighbours = parseLldpNeighbours(doc, { linkStateOf });
    let chassisId = null;
    try {
      const c = await run('lldpcli', ['-f', 'json', 'show', 'chassis']);
      if (!c.err || c.stdout) chassisId = parseLocalChassisId(c.stdout);
    } catch { chassisId = null; }
    return { neighbours, chassisId };
  } catch (err) {
    return { unavailable: `lldpctl failed: ${String((err && err.message) || 'error').slice(0, 120)}` };
  }
}

module.exports = { collectLldp, parseLldpNeighbours, parseLocalChassisId, MAX_NEIGHBOURS };
