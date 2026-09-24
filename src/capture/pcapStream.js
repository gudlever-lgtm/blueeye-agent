'use strict';

// Incremental parser for the classic pcap stream `tcpdump -w -` writes on stdout.
//
// WHY A STREAM AND NOT A FILE. A capture that lands on disk is a capture that
// outlives the process, survives a crash, and can be copied. Reading tcpdump's
// stdout means the frames exist only as bytes in flight between two processes:
// the agent decodes each one into a header record (capture/decode.js) and drops
// the buffer. Nothing to delete afterwards, because nothing was written.
//
// Format (all fields native-endian per the magic):
//   global header, 24 bytes:  magic u32 | major u16 | minor u16 | zone i32 |
//                             sigfigs u32 | snaplen u32 | linktype u32
//   per packet, 16 bytes:     ts_sec u32 | ts_frac u32 | incl_len u32 | orig_len u32
//   then incl_len bytes of frame.
//
// The four magics differ in byte order and in whether ts_frac is micro- or
// nanoseconds. All four are accepted: which one a host's tcpdump emits depends
// on its libpcap version, and getting the timestamp scale wrong turns a 30 ms
// handshake into a 30 µs one.

const GLOBAL_HEADER_LEN = 24;
const PACKET_HEADER_LEN = 16;

// A frame larger than this is not a frame — it is a desynchronised stream or a
// corrupt header, and allocating on that number is how a parser becomes a
// memory bug. tcpdump is started with a small snaplen, so the real values are
// two orders of magnitude below this.
const MAX_FRAME_BYTES = 262144;

const MAGICS = Object.freeze({
  0xa1b2c3d4: { littleEndian: false, nanos: false },
  0xd4c3b2a1: { littleEndian: true, nanos: false },
  0xa1b23c4d: { littleEndian: false, nanos: true },
  0x4d3cb2a1: { littleEndian: true, nanos: true },
});

function createPcapParser() {
  let buf = Buffer.alloc(0);
  let header = null;   // { littleEndian, nanos, linkType, snaplen }
  let baseSec = null;  // the first packet's second, so `t` is ms since capture start
  let baseFrac = 0;
  let failed = null;

  const u32 = (b, o) => (header.littleEndian ? b.readUInt32LE(o) : b.readUInt32BE(o));

  function readGlobalHeader() {
    if (buf.length < GLOBAL_HEADER_LEN) return false;
    const magicBE = buf.readUInt32BE(0);
    const spec = MAGICS[magicBE];
    if (!spec) { failed = `unrecognised pcap magic 0x${magicBE.toString(16)}`; return false; }
    header = { ...spec, linkType: 0, snaplen: 0 };
    header.linkType = u32(buf, 20);
    header.snaplen = u32(buf, 16);
    buf = buf.subarray(GLOBAL_HEADER_LEN);
    return true;
  }

  // Feeds bytes in and returns every complete frame they completed, as
  // { frame, tsMs, capLen, wireLen }. Incomplete trailing bytes are kept for the
  // next call — tcpdump's pipe splits wherever the kernel felt like it, and a
  // frame boundary almost never lands on a chunk boundary.
  function push(chunk) {
    if (failed) return [];
    if (chunk && chunk.length) buf = buf.length ? Buffer.concat([buf, chunk]) : Buffer.from(chunk);
    if (!header && !readGlobalHeader()) return [];

    const out = [];
    for (;;) {
      if (buf.length < PACKET_HEADER_LEN) break;
      const tsSec = u32(buf, 0);
      const tsFrac = u32(buf, 4);
      const capLen = u32(buf, 8);
      const wireLen = u32(buf, 12);
      if (capLen > MAX_FRAME_BYTES) { failed = `implausible frame length ${capLen}`; return out; }
      if (buf.length < PACKET_HEADER_LEN + capLen) break;

      const frame = buf.subarray(PACKET_HEADER_LEN, PACKET_HEADER_LEN + capLen);
      buf = buf.subarray(PACKET_HEADER_LEN + capLen);

      if (baseSec === null) { baseSec = tsSec; baseFrac = tsFrac; }
      const divisor = header.nanos ? 1e6 : 1e3; // → milliseconds
      const tsMs = (tsSec - baseSec) * 1000 + (tsFrac - baseFrac) / divisor;

      // Copied, not referenced: `subarray` shares the accumulator's memory, and
      // holding a view would pin every byte the pipe has delivered.
      out.push({ frame: Buffer.from(frame), tsMs, capLen, wireLen });
    }
    return out;
  }

  return {
    push,
    linkType: () => (header ? header.linkType : null),
    snaplen: () => (header ? header.snaplen : null),
    error: () => failed,
    pending: () => buf.length,
  };
}

module.exports = { createPcapParser, GLOBAL_HEADER_LEN, PACKET_HEADER_LEN, MAX_FRAME_BYTES };
