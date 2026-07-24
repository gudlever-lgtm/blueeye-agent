'use strict';

const RUN_TEST = /^run[\s_-]?test$/i;
const RUN_PROBE = /^run[\s_-]?probe$/i;
const PING = /^ping$/i;
const UPDATE = /^(update|self[\s_-]?update|upgrade)$/i;
const SPEEDTEST = /^speed[\s_-]?test$/i;
const DIAGNOSE = /^(diagnose|diag|doctor|self[\s_-]?check|health[\s_-]?check)$/i;
const DELETE = /^(delete|self[\s_-]?delete|uninstall)$/i;
const INSTALL_TOOL = /^install[\s_-]?tool$/i;
const EVIDENCE = /^evidence(?:[\s_-]?snapshot)?$/i;
const RUN_DISCOVERY = /^(run[\s_-]?discovery|discovery[\s_-]?sweep|sweep)$/i;

function verbOf(command) {
  if (typeof command === 'string') return command.trim();
  if (command && typeof command === 'object') {
    const v = command.name || command.action || command.type || command.command;
    return typeof v === 'string' ? v.trim() : '';
  }
  return '';
}

// Recognises a "run test" command. The server sends commands as
// { type: 'command', command: <X> }; X may be a string ("run test") or an
// object carrying name/action/type (e.g. { name: 'run-test', id: 7 }).
function isRunTestCommand(command) {
  return RUN_TEST.test(verbOf(command));
}

// Recognises a "run probe" command: { name: 'run-probe', probe: { type, ... } }.
function isRunProbeCommand(command) {
  return RUN_PROBE.test(verbOf(command)) && !!command && typeof command.probe === 'object' && command.probe !== null;
}

// Recognises a "ping" liveness command: { name: 'ping', id } — the agent replies
// with an ack carrying its version/sources so the server can confirm the link.
function isPingCommand(command) {
  return PING.test(verbOf(command));
}

// Recognises a self-update command: { name: 'update', id, sha256 } — rebuild from
// the server's source bundle and restart (systemd-managed agents only).
function isUpdateCommand(command) {
  return UPDATE.test(verbOf(command));
}

// Recognises a speed-test command: { name: 'speedtest', bytes? } — download then
// upload a sized blob to/from the server and report the achieved Mbps.
function isSpeedtestCommand(command) {
  return SPEEDTEST.test(verbOf(command));
}

// Recognises a diagnose command: { name: 'diagnose', id } — introspect the flow
// pipeline (source, collector binding, datagrams/flows seen, exporter state) and
// report it back so the dashboard can show where flows stop. Read-only.
function isDiagnoseCommand(command) {
  return DIAGNOSE.test(verbOf(command));
}

// Recognises a delete command: { name: 'delete', id, auditId } — stop the
// service, securely wipe the token and remove the install directory (the agent
// removes itself from this host). Docker-managed agents decline.
function isDeleteCommand(command) {
  return DELETE.test(verbOf(command));
}

// Recognises an install-tool command: { name: 'install-tool', id, auditId,
// tool } — install a missing diagnostic tool (e.g. traceroute) from the host's
// package manager and report back. The agent only installs tools on its own
// allowlist (see src/toolInstaller.js); a missing `tool` is not this command.
function isInstallToolCommand(command) {
  return INSTALL_TOOL.test(verbOf(command)) && !!command && typeof command.tool === 'string' && command.tool.trim() !== '';
}

// Recognises a read-only evidence-snapshot command: { name: 'evidence', id,
// snapshotId, clusterId, commandSetVersion, items:[...], signature? }. The agent
// collects ONLY the items on its own read-only allowlist (src/evidenceCollector.js)
// and replies with per-item results — never a write action.
function isEvidenceCommand(command) {
  return EVIDENCE.test(verbOf(command));
}

// Recognises a "run discovery" command: { name: 'run-discovery', discovery: {
// cidrs?, ports?, rateLimit?, addressCap?, requestId? } } — sweep the configured
// CIDR scope from THIS agent's network vantage (empty scope ⇒ the agent's own
// subnet) and report the live hosts back. Native probes only, rate-limited,
// scope-capped; never a write action.
function isRunDiscoveryCommand(command) {
  return RUN_DISCOVERY.test(verbOf(command)) && !!command && typeof command.discovery === 'object' && command.discovery !== null;
}

module.exports = { isRunTestCommand, isRunProbeCommand, isPingCommand, isUpdateCommand, isSpeedtestCommand, isDiagnoseCommand, isDeleteCommand, isInstallToolCommand, isEvidenceCommand, isRunDiscoveryCommand };
