'use strict';

const { decodeSampledHeader } = require('./decodePacket');

// Parses an sFlow v5 datagram (UDP). sFlow is sampling-based: the agent on the
// switch captures 1-in-N packets and exports the first bytes of each sampled
// frame plus the sampling rate. To estimate real traffic we scale each sample's
// bytes by its rate. We decode "flow samples" (type 1) containing a "raw packet
// header" flow record (type 1) — the common case for port/protocol visibility.
//
// Datagram layout (v5): version(4)=5 ipVersion(4) agentAddr(4|16) subAgentId(4)
// seq(4) uptime(4) numSamples(4) then numSamples samples. Each sample:
// sampleType(4) sampleLength(4) body.
//
// Returns { header, flows } where flows match the NetFlow flow shape (bytes are
// rate-scaled). Throws on a malformed/too-short datagram.
function parseSflow(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 28) {
    throw new Error('sFlow: datagram too short');
  }
  const version = buf.readUInt32BE(0);
  if (version !== 5) {
    throw new Error(`sFlow: unsupported version ${version}`);
  }
  const ipVersion = buf.readUInt32BE(4);
  let o = 8;
  o += ipVersion === 2 ? 16 : 4; // agent address (IPv6 vs IPv4)
  o += 4; // sub-agent id
  o += 4; // sequence
  o += 4; // uptime
  if (o + 4 > buf.length) throw new Error('sFlow: truncated header');
  const numSamples = buf.readUInt32BE(o);
  o += 4;

  const header = { version, numSamples };
  const flows = [];

  for (let s = 0; s < numSamples && o + 8 <= buf.length; s += 1) {
    const sampleType = buf.readUInt32BE(o);
    const sampleLen = buf.readUInt32BE(o + 4);
    const sampleStart = o + 8;
    const sampleEnd = sampleStart + sampleLen;
    if (sampleLen < 0 || sampleEnd > buf.length) break;

    // sampleType 1 = flow sample, 3 = expanded flow sample. (1=enterprise 0)
    if (sampleType === 1 || sampleType === 3) {
      parseFlowSample(buf, sampleStart, sampleEnd, sampleType === 3, flows);
    }
    o = sampleEnd;
  }

  return { header, flows };
}

function parseFlowSample(buf, start, end, expanded, flows) {
  let p = start;
  p += 4; // sequence number
  // source id: 4 bytes (normal) or 8 bytes (expanded)
  p += expanded ? 8 : 4;
  if (p + 16 > end) return;
  const samplingRate = buf.readUInt32BE(p); p += 4;
  p += 4; // sample pool
  p += 4; // drops
  // input/output interface: 4 each (normal) or 8 each (expanded)
  p += expanded ? 16 : 8;
  if (p + 4 > end) return;
  const numRecords = buf.readUInt32BE(p); p += 4;

  const rate = samplingRate > 0 ? samplingRate : 1;

  for (let r = 0; r < numRecords && p + 8 <= end; r += 1) {
    const recType = buf.readUInt32BE(p);
    const recLen = buf.readUInt32BE(p + 4);
    const recStart = p + 8;
    const recEnd = recStart + recLen;
    if (recEnd > end) break;

    // flow record type 1 = raw packet header (enterprise 0).
    if (recType === 1 && recStart + 16 <= recEnd) {
      // header_protocol(4) frame_length(4) stripped(4) header_length(4) header[]
      const frameLength = buf.readUInt32BE(recStart + 4);
      const headerLength = buf.readUInt32BE(recStart + 12);
      const hStart = recStart + 16;
      const hEnd = Math.min(hStart + headerLength, recEnd);
      if (hEnd > hStart) {
        const flow = decodeSampledHeader(buf.subarray(hStart, hEnd), frameLength);
        if (flow) {
          // Scale by the sampling rate: each sample stands in for ~rate packets.
          flow.bytes *= rate;
          flow.packets *= rate;
          flow.sampled = true;
          flows.push(flow);
        }
      }
    }
    p = recEnd;
  }
}

module.exports = { parseSflow };
