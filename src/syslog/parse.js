'use strict';

// Pure syslog line parser. No I/O, no clock, no sockets — a string in, a plain
// object (or null) out, so the whole format matrix is testable without binding
// a port.
//
// Four dialects reach a collector in practice, and the format is detected PER
// LINE rather than per sender: one device can emit more than one of them (a
// switch logs RFC 3164 and its management daemon logs RFC 5424), and a UDP
// datagram from one host says nothing about the next. This is the same rule
// blueeye-server's src/identity/arpTable.js follows for the same reason — an
// unparseable line must never discard the rest of the batch.
//
//   1. RFC 5424   <34>1 2026-09-20T09:41:09.000Z sw-core-1 - - ID47 [sd] msg
//   2. RFC 3164   <186>Sep 20 09:41:09 sw-core-1 %LINK-3-UPDOWN: Interface ...
//   3. Cisco 3164 <186>4521: sw-core-1: Sep 20 09:41:09.123 CEST: %LINK-3-...
//   4. RFC 3339   <78>2026-09-24T01:42:47.794495+00:00 vm CRON[15734]: msg
//      (BSD layout with a full ISO stamp and no version digit — rsyslog's
//      RSYSLOG_ForwardFormat, and what `$ActionForwardDefaultTemplate` users
//      send; captured in test/fixtures/syslog/real-captured.txt)
//   5. PRI only   <186>anything at all
//
// Anything with no PRI at all is NOT syslog and returns null: accepting it would
// mean inventing a facility and a severity, and a severity nobody measured is
// worse than a line nobody stored.

const MONTHS = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

// <PRI> is 1-3 digits. A PRI above 191 (facility 23, severity 7) is out of
// range and the line is treated as unparseable rather than clamped.
const PRI_RE = /^<(\d{1,3})>/;

// RFC 3164 stamp: "Sep 20 09:41:09" or "Sep  9 09:41:09" (space-padded day).
// Cisco appends fractional seconds and often a zone: "Sep 20 09:41:09.123 CEST".
// With `service timestamps log datetime year` IOS also puts the YEAR between
// the day and the time ("Apr 19 2018 18:00:06"); that year is used as given.
const BSD_STAMP_RE = /^([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?/;

// Cisco's leading sequence number ("4521: ") and/or uptime marker ("*" / ".").
const CISCO_SEQ_RE = /^(?:\d+:\s*)?(?:[*.])?/;

// RFC 5424 stamp is ISO 8601 and Date can read it directly; guard the shape so a
// malformed one falls through to "no device time" instead of Invalid Date.
const ISO_STAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const SEVERITY_NAME = [
  'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug',
];

// Resolves an RFC 3164 stamp, which carries no year, against the time the line
// was RECEIVED. A December log read on 1 January belongs to the year before, so
// a stamp more than a day in the future rolls back rather than landing 12 months
// out — the one case where guessing beats not guessing, because the alternative
// (no device time at all) loses the clock-skew check the UI is built around.
function resolveBsdYear(month, day, hh, mm, ss, ms, receivedAt) {
  const recv = new Date(receivedAt);
  let year = recv.getUTCFullYear();
  let d = new Date(Date.UTC(year, month, day, hh, mm, ss, ms));
  if (d.getTime() - recv.getTime() > 86400000) {
    year -= 1;
    d = new Date(Date.UTC(year, month, day, hh, mm, ss, ms));
  }
  return d;
}

// Splits "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down" or
// "sshd[1234]: Failed password" into { tag, message }. The tag is what names the
// event; classify.js reads it. A line with no tag keeps the whole text.
function splitTag(text) {
  // An EMPTY tag (`logger -t ""`, or a relay that blanks it) leaves the bare
  // colon: "vm : %LINK-3-UPDOWN: …". Drop it so the message starts where the
  // sender's text starts, rather than keeping ": " as its first two bytes.
  const empty = /^:\s?(?=\S)/.exec(text);
  if (empty) return { tag: null, procId: null, message: text.slice(empty[0].length) };
  const m = /^([^\s:[]{1,48})(?:\[(\d{1,10})\])?:\s?(.*)$/s.exec(text);
  if (!m) return { tag: null, procId: null, message: text };
  return { tag: m[1], procId: m[2] || null, message: m[3] };
}

// Parses one syslog line. `receivedAt` (ms epoch) resolves the year for the
// dialects that omit it; it is a parameter rather than Date.now() so the parser
// stays pure and the tests stay deterministic.
//
// Returns null when the line carries no usable PRI. Never throws.
function parseSyslogLine(line, { receivedAt = 0 } = {}) {
  if (typeof line !== 'string') return null;
  let raw = line.replace(/\0/g, '').trim();
  if (!raw) return null;
  // An RFC 6587 octet-count frame ("123 <PRI>…") sent over UDP, where no
  // framing belongs (`logger --octet-count`, some relays). A real line starts
  // with its PRI, so digits + space + '<' can only be a frame: strip it rather
  // than drop the message.
  const frame = /^\d{1,6} (?=<\d{1,3}>)/.exec(raw);
  if (frame) raw = raw.slice(frame[0].length);

  const pri = PRI_RE.exec(raw);
  if (!pri) return null;
  const priValue = Number(pri[1]);
  if (!Number.isInteger(priValue) || priValue > 191) return null;

  const facility = priValue >> 3;
  const severity = priValue & 7;
  let rest = raw.slice(pri[0].length);

  // --- RFC 5424: a version digit and a space directly after the PRI ---------
  const ver = /^(\d{1,2})\s/.exec(rest);
  if (ver && ver[1] === '1') {
    const parts = rest.slice(ver[0].length).split(' ');
    const [stamp, host, appName, procId, msgId] = parts;
    // STRUCTURED-DATA is "-" or one or more [...] groups; the MSG is whatever
    // follows. We keep the message and drop the SD: it is vendor key/value
    // detail, and every field we would keep is already a column.
    const after = parts.slice(5).join(' ');
    const sd = /^(?:-|(?:\[[^\]]*\]\s*)+)/.exec(after);
    const message = (sd ? after.slice(sd[0].length) : after).trim();
    return {
      raw,
      facility,
      severity,
      severityName: SEVERITY_NAME[severity],
      deviceTime: ISO_STAMP_RE.test(stamp || '') ? new Date(stamp) : null,
      host: host && host !== '-' ? host : null,
      tag: appName && appName !== '-' ? appName : null,
      procId: procId && procId !== '-' ? procId : null,
      msgId: msgId && msgId !== '-' ? msgId : null,
      message: message || after.trim(),
      format: 'rfc5424',
    };
  }

  // --- Cisco's sequence number / uptime marker, if present ------------------
  const seq = CISCO_SEQ_RE.exec(rest);
  if (seq && seq[0]) rest = rest.slice(seq[0].length);

  // Cisco also puts the hostname BEFORE the timestamp ("sw-core-1: Sep 20 ...",
  // `logging origin-id hostname`). Only treat a leading token as the host when
  // a BSD stamp follows it, so an ordinary tagged message is not mistaken for
  // one. The stamp may carry the uptime/unsynced marker ("*Sep 24 ...") and the
  // `datetime year` year ("Apr 19 2018 18:00:06") — without both, the real
  // `52: sw-core-1: *Sep 24 08:21:50.123: %LINK-3-UPDOWN: …` shape put the
  // HOSTNAME in the tag and the line came out syslog.raw.
  let host = null;
  const hostFirst = /^([A-Za-z0-9][A-Za-z0-9._-]{0,62}):\s+[*.]?(?=[A-Za-z]{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:)/.exec(rest);
  if (hostFirst) {
    host = hostFirst[1];
    rest = rest.slice(hostFirst[0].length);
  }

  // --- RFC 3339 stamp in the BSD position (dialect 4) ------------------------
  // Without this the stamp's "2026-09-24T01" was split off as the TAG, the host
  // was lost and the device time dropped. The Cisco sequence regex above cannot
  // eat any of it ("2026-" is not "digits:"), so the stamp is intact here.
  const iso = !host && /^(\S+)\s+/.exec(rest);
  if (iso && ISO_STAMP_RE.test(iso[1])) {
    const after = rest.slice(iso[0].length);
    const h = /^([A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+/.exec(after);
    const split = splitTag(h ? after.slice(h[0].length) : after);
    return {
      raw,
      facility,
      severity,
      severityName: SEVERITY_NAME[severity],
      deviceTime: new Date(iso[1]),
      host: h ? h[1] : null,
      tag: split.tag,
      procId: split.procId,
      msgId: null,
      message: split.message,
      format: 'rfc3164',
    };
  }

  // --- RFC 3164 timestamp ---------------------------------------------------
  const bsd = BSD_STAMP_RE.exec(rest);
  let deviceTime = null;
  if (bsd) {
    const month = MONTHS[bsd[1].toLowerCase()];
    if (month !== undefined) {
      const ms = bsd[7] ? Number(String(bsd[7]).padEnd(3, '0').slice(0, 3)) : 0;
      deviceTime = bsd[3]
        ? new Date(Date.UTC(Number(bsd[3]), month, Number(bsd[2]), Number(bsd[4]), Number(bsd[5]), Number(bsd[6]), ms))
        : resolveBsdYear(month, Number(bsd[2]), Number(bsd[4]), Number(bsd[5]), Number(bsd[6]), ms, receivedAt);
    }
    rest = rest.slice(bsd[0].length);
    // A trailing zone name ("CEST:") or the colon Cisco puts after the stamp.
    rest = rest.replace(/^\s*(?:[A-Z]{2,5}\s*)?:?\s*/, '');
    // The hostname sits after the stamp in plain BSD format.
    if (!host) {
      const h = /^([A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+/.exec(rest);
      if (h) {
        host = h[1];
        rest = rest.slice(h[0].length);
      }
    }
  }

  const { tag, procId, message } = splitTag(rest);
  return {
    raw,
    facility,
    severity,
    severityName: SEVERITY_NAME[severity],
    deviceTime,
    host,
    tag,
    procId,
    msgId: null,
    message,
    format: bsd ? 'rfc3164' : 'pri-only',
  };
}

module.exports = { parseSyslogLine, SEVERITY_NAME };
