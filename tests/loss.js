import os from 'node:os';
import { runCommand } from './exec.js';

const PACKETS = 50;

// Parser pakke-tab fra ping-opsummeringen.
export function parseLoss(stdout) {
  const transmitted = stdout.match(/(\d+)\s+packets transmitted/);
  const received = stdout.match(/(\d+)\s+(?:packets\s+)?received/);
  const lossMatch = stdout.match(/([\d.]+)%\s+packet loss/);

  if (!lossMatch) {
    throw new Error('Kunne ikke parse packet loss');
  }

  const sent = transmitted ? Number(transmitted[1]) : PACKETS;
  const got = received ? Number(received[1]) : null;

  return {
    sent,
    received: got,
    lossPercent: Number(lossMatch[1]),
  };
}

export async function run(target, options = {}, signal) {
  const isWindows = os.platform() === 'win32';
  const args = isWindows
    ? ['-n', String(PACKETS), target]
    : ['-c', String(PACKETS), target];

  const { stdout } = await runCommand('ping', args, { signal });
  return parseLoss(stdout);
}
