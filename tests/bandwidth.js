import { runCommand, isMissingBinary } from './exec.js';

// Parser send/receive Mbps og retransmits fra iperf3 JSON (TCP-test).
export function parseBandwidth(stdout) {
  const data = JSON.parse(stdout);

  if (data.error) {
    throw new Error(data.error);
  }

  const end = data.end;
  if (!end?.sum_sent || !end?.sum_received) {
    throw new Error('iperf3-output mangler sender/receiver-summary');
  }

  return {
    sendMbps: Number(((end.sum_sent.bits_per_second ?? 0) / 1e6).toFixed(1)),
    receiveMbps: Number(((end.sum_received.bits_per_second ?? 0) / 1e6).toFixed(1)),
    retransmits: Number(end.sum_sent.retransmits ?? 0),
  };
}

export async function run(target, options = {}, signal) {
  try {
    const { stdout } = await runCommand(
      'iperf3',
      ['-c', target, '-t', '10', '-J'],
      { signal }
    );
    return parseBandwidth(stdout);
  } catch (err) {
    if (isMissingBinary(err)) {
      throw new Error('iperf3 not installed');
    }
    throw err;
  }
}
