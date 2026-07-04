'use strict';

// Extracts a value from an HTTP response for use by later steps. Three kinds:
//   regex  — capture group 1 (or the whole match) of `pattern` against the body
//   cookie — the value of the Set-Cookie named `pattern`
//   json   — a dotted path (`data.token`) into the JSON body
// Returns the extracted string, or null when it doesn't match / can't parse.
// Extracted values stay on the agent and are never reported.
function extract(spec, { body = '', headers = {} } = {}) {
  const type = (spec && spec.type) || 'regex';
  const pattern = spec && spec.pattern != null ? String(spec.pattern) : '';
  if (!pattern) return null;

  if (type === 'regex') {
    try {
      const m = new RegExp(pattern).exec(String(body || ''));
      if (!m) return null;
      return m[1] !== undefined ? m[1] : m[0];
    } catch { return null; }
  }

  if (type === 'cookie') {
    const raw = headers['set-cookie'];
    const cookies = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    const esc = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    for (const c of cookies) {
      const m = new RegExp(`(?:^|;\\s*)${esc}=([^;]*)`).exec(String(c));
      if (m) return m[1];
    }
    return null;
  }

  if (type === 'json') {
    let obj;
    try { obj = JSON.parse(String(body || '')); } catch { return null; }
    let cur = obj;
    for (const key of pattern.split('.').filter(Boolean)) {
      if (cur == null || typeof cur !== 'object') return null;
      cur = cur[key];
    }
    if (cur == null) return null;
    return typeof cur === 'object' ? JSON.stringify(cur) : String(cur);
  }

  return null;
}

module.exports = { extract };
