'use strict';

// Formats raw big-endian address bytes as a string. Shared by the v9/IPFIX and
// v5 field decoders and the sFlow packet decoder.
function ipv4(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function ipv6(buf, off) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
  return parts.join(':');
}

module.exports = { ipv4, ipv6 };
