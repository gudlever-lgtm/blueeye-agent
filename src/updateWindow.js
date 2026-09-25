'use strict';

// A maintenance window for self-updates, as 'HH:MM-HH:MM' in the AGENT's local
// time. Empty means any time.
//
// The agent is what evaluates it, because only the agent knows its own local
// time — a fleet spread over three time zones cannot have "02:00" decided
// centrally. The server validates the string and passes it down; this module is
// byte-identical in blueeye-server (src/lib/updateWindow.js) so both sides agree on
// what a window means, including the part below that is easy to get wrong.
//
// A window may WRAP midnight: '22:00-04:00' is the four hours after ten at
// night plus the four before four in the morning, not an empty range. The
// nightly window people actually want is the wrapping one, so treating it as
// empty would silently mean "never update".
//
// Both ends are inclusive of the start and exclusive of the end, so two adjacent
// windows never both match the same minute.

// Returns { startMin, endMin } in minutes past local midnight, or null when the
// string is absent or not a window. A window of zero length ('02:00-02:00') is
// not a window: it would match nothing, and reading it as "always" is the kind
// of guess that pushes code at lunchtime.
function parseWindow(value) {
  const m = /^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$/.exec(String(value || ''));
  if (!m) return null;
  const [sh, sm, eh, em] = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (sh > 23 || eh > 23 || sm > 59 || em > 59) return null;
  const startMin = sh * 60 + sm;
  const endMin = eh * 60 + em;
  if (startMin === endMin) return null;
  return { startMin, endMin };
}

// Is `date` (local time) inside the window? An empty/unparseable window means no
// restriction — true — because a window nobody set must not stop updates, and a
// window nobody can read is reported by the validator long before this.
function isWithinWindow(value, date = new Date()) {
  const w = parseWindow(value);
  if (!w) return true;
  const minutes = date.getHours() * 60 + date.getMinutes();
  if (w.startMin < w.endMin) return minutes >= w.startMin && minutes < w.endMin;
  // Wrapping midnight: inside means "after the start OR before the end".
  return minutes >= w.startMin || minutes < w.endMin;
}

module.exports = { parseWindow, isWithinWindow };
