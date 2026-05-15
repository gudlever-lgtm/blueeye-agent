import { runCommand, isMissingBinary } from './exec.js';

const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// Parser dig +short +stats output.
export function parseDig(stdout) {
  const resolved = [];
  let queryTimeMs = null;
  let ttl = null;

  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (IPV4.test(trimmed)) {
      resolved.push(trimmed);
      continue;
    }
    const qt = trimmed.match(/Query time:\s*([\d.]+)\s*msec/);
    if (qt) queryTimeMs = Number(qt[1]);
    const ttlMatch = trimmed.match(/\bIN\s+A\s+(\d+)/i);
    if (ttlMatch && ttl === null) ttl = Number(ttlMatch[1]);
  }

  return { resolved, queryTimeMs, ttl };
}

// Parser nslookup-output som fallback.
export function parseNslookup(stdout) {
  const resolved = [];
  const lines = stdout.split(/\r?\n/);

  // Spring serverens egen adresse over (de første Address-linjer).
  let pastServer = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^Name:/i.test(trimmed)) pastServer = true;
    const addr = trimmed.match(/Address(?:es)?:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
    if (addr && pastServer) resolved.push(addr[1]);
  }

  return { resolved, queryTimeMs: null, ttl: null };
}

export async function run(target, options = {}, signal) {
  try {
    const { stdout } = await runCommand(
      'dig',
      ['+short', '+stats', target],
      { signal }
    );
    return parseDig(stdout);
  } catch (err) {
    if (!isMissingBinary(err)) throw err;
  }

  // Fallback til nslookup.
  try {
    const { stdout } = await runCommand('nslookup', [target], { signal });
    return parseNslookup(stdout);
  } catch (err) {
    if (isMissingBinary(err)) {
      throw new Error('dig and nslookup not installed');
    }
    throw err;
  }
}
