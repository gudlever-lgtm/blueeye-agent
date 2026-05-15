import os from 'node:os';
import { runCommand } from './exec.js';

// Parser traceroute/tracert-output linje for linje til hop-objekter.
export function parseTraceroute(stdout) {
  const hops = [];

  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    const hopMatch = trimmed.match(/^(\d+)\s+(.*)$/);
    if (!hopMatch) continue;

    const hop = Number(hopMatch[1]);
    const rest = hopMatch[2];

    const ipMatch = rest.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const latencyMatch = rest.match(/([\d.]+)\s*ms/);

    hops.push({
      hop,
      ip: ipMatch ? ipMatch[1] : '*',
      latencyMs: latencyMatch ? Number(latencyMatch[1]) : null,
    });
  }

  return { hops };
}

export async function run(target, options = {}, signal) {
  const isWindows = os.platform() === 'win32';
  const cmd = isWindows ? 'tracert' : 'traceroute';
  const args = isWindows ? ['-d', target] : ['-n', target];

  const { stdout } = await runCommand(cmd, args, { signal });
  return parseTraceroute(stdout);
}
