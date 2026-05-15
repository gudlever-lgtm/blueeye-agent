import os from 'node:os';
import { runCommand } from './exec.js';

// Parser curl -w output: "<http_code> <time_total> <time_starttransfer> <size_download>".
// Tider er i sekunder fra curl og konverteres til ms.
export function parseCurl(raw) {
  const parts = raw.trim().split(/\s+/);
  if (parts.length < 4) {
    throw new Error('Kunne ikke parse curl-output');
  }

  const statusCode = Number(parts[0]);
  const result = {
    statusCode,
    responseTimeMs: Number((Number(parts[1]) * 1000).toFixed(1)),
    ttfbMs: Number((Number(parts[2]) * 1000).toFixed(1)),
    contentLength: Number(parts[3]),
  };

  if (statusCode === 404 || statusCode === 500) {
    const err = new Error(`HTTP ${statusCode}`);
    err.result = result;
    throw err;
  }

  return result;
}

export async function run(target, options = {}, signal) {
  const nullDevice = os.platform() === 'win32' ? 'NUL' : '/dev/null';
  const { stdout } = await runCommand(
    'curl',
    [
      '-o', nullDevice,
      '-s',
      '-w', '%{http_code} %{time_total} %{time_starttransfer} %{size_download}',
      target,
    ],
    { signal }
  );
  return parseCurl(stdout);
}
