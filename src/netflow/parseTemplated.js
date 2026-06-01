'use strict';

const { applyField, finaliseFlow } = require('./fields');

// Parses NetFlow v9 (version 9) and IPFIX (version 10) export packets. Both are
// template-based: the exporter sends Template FlowSets that define the layout of
// later Data FlowSets. Templates arrive in their own packets and must be cached
// across packets, so the caller passes a persistent `templates` Map
// (key `${version}:${sourceId}:${templateId}` -> [{ type, length }]).
//
// Returns { header, flows, templatesLearned }. Data records for an unknown
// template are skipped (counted) until the template is seen — standard behaviour.
//
// Header layouts:
//   v9 (20 bytes):   version(2) count(2) sysUptime(4) unixSecs(4) seq(4) sourceId(4)
//   IPFIX (16 bytes): version(2) length(2) exportTime(4) seq(4) obsDomainId(4)
// FlowSet: id(2) length(2) then content. id 0 (v9) / 2 (IPFIX) = template,
// id 1 (v9) / 3 (IPFIX) = options template (skipped), id >= 256 = data.
function parseTemplated(buf, templates = new Map()) {
  if (!Buffer.isBuffer(buf) || buf.length < 16) {
    throw new Error('Templated NetFlow: packet too short');
  }
  const version = buf.readUInt16BE(0);
  if (version !== 9 && version !== 10) {
    throw new Error(`Templated NetFlow: unexpected version ${version}`);
  }

  let offset;
  let sourceId;
  let header;
  if (version === 9) {
    const count = buf.readUInt16BE(2);
    header = { version, count, sysUptimeMs: buf.readUInt32BE(4), unixSecs: buf.readUInt32BE(8) };
    sourceId = buf.readUInt32BE(16);
    offset = 20;
  } else {
    const length = buf.readUInt16BE(2);
    header = { version, length, unixSecs: buf.readUInt32BE(4) };
    sourceId = buf.readUInt32BE(12);
    offset = 16;
  }

  const TEMPLATE_SETID = version === 9 ? 0 : 2;
  const OPTIONS_SETID = version === 9 ? 1 : 3;
  const flows = [];
  let templatesLearned = 0;
  let skippedNoTemplate = 0;

  while (offset + 4 <= buf.length) {
    const setId = buf.readUInt16BE(offset);
    const setLen = buf.readUInt16BE(offset + 2);
    if (setLen < 4 || offset + setLen > buf.length) break; // malformed / padding
    const setEnd = offset + setLen;
    let p = offset + 4;

    if (setId === TEMPLATE_SETID) {
      // One or more template records.
      while (p + 4 <= setEnd) {
        const templateId = buf.readUInt16BE(p);
        const fieldCount = buf.readUInt16BE(p + 2);
        p += 4;
        const fields = [];
        for (let i = 0; i < fieldCount && p + 4 <= setEnd; i += 1) {
          const type = buf.readUInt16BE(p);
          const len = buf.readUInt16BE(p + 2);
          p += 4;
          // IPFIX enterprise fields carry an extra 4-byte PEN — skip it.
          if (version === 10 && (type & 0x8000) !== 0) p += 4;
          fields.push({ type: type & 0x7fff, length: len });
        }
        templates.set(`${version}:${sourceId}:${templateId}`, fields);
        templatesLearned += 1;
      }
    } else if (setId === OPTIONS_SETID) {
      // Options templates — not needed for flow records; skip the whole set.
    } else if (setId >= 256) {
      const fields = templates.get(`${version}:${sourceId}:${setId}`);
      if (!fields) {
        skippedNoTemplate += 1;
      } else {
        const recLen = fields.reduce((s, f) => s + f.length, 0);
        if (recLen > 0) {
          while (p + recLen <= setEnd) {
            const flow = {};
            let fo = p;
            for (const f of fields) {
              applyField(flow, f.type, buf, fo, f.length);
              fo += f.length;
            }
            flows.push(finaliseFlow(flow));
            p += recLen;
          }
        }
      }
    }

    offset = setEnd;
  }

  return { header, flows, templatesLearned, skippedNoTemplate };
}

module.exports = { parseTemplated };
