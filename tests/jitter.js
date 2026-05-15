import { runCommand, isMissingBinary } from './exec.js';

// Parser jitter, tab og bandwidth fra iperf3 JSON (UDP-test).
export function parseJitter(stdout) {
  const data = JSON.parse(stdout);

  if (data.error) {
    throw new Error(data.error);
  }

  const sum = data.end?.sum;
  if (!sum) {
    throw new Error('iperf3-output mangler receiver-summary');
  }

  return {
    jitterMs: Number(sum.jitter_ms ?? 0),
    lossPercent: Number(sum.lost_percent ?? 0),
    bandwidthMbps: Number(((sum.bits_per_second ?? 0) / 1e6).toFixed(1)),
  };
}

export async function run(target, options = {}, signal) {
  try {
    const { stdout } = await runCommand(
      'iperf3',
      ['-c', target, '-u', '-t', '10', '-J'],
      { signal }
    );
    return parseJitter(stdout);
  } catch (err) {
    if (isMissingBinary(err)) {
      throw new Error('iperf3 not installed');
    }
    throw err;
  }
}
