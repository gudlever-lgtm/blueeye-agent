import os from 'node:os';
import { runCommand } from './exec.js';

const PACKETS = 10;

// Parser sidste opsummeringslinje fra ping til min/avg/max/stddev.
export function parsePing(stdout) {
  const summary = stdout.match(
    /=\s*([\d.]+)\/([\d.]+)\/([\d.]+)(?:\/([\d.]+))?\s*ms/
  );
  const sent = stdout.match(/(\d+)\s+packets transmitted/);

  if (!summary) {
    throw new Error('Kunne ikke parse ping-output');
  }

  return {
    avgMs: Number(summary[2]),
    minMs: Number(summary[1]),
    maxMs: Number(summary[3]),
    stddevMs: summary[4] !== undefined ? Number(summary[4]) : null,
    packets: sent ? Number(sent[1]) : PACKETS,
  };
}

export async function run(target, options = {}, signal) {
  const isWindows = os.platform() === 'win32';
  const args = isWindows
    ? ['-n', String(PACKETS), target]
    : ['-c', String(PACKETS), target];

  const { stdout } = await runCommand('ping', args, { signal });
  return parsePing(stdout);
}
