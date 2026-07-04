'use strict';

// Substitutes {{secret:name}} (from decrypted secrets) and {{var}} (from values
// extracted by earlier steps) in a string. Secrets are resolved first (their
// pattern carries a colon, which the {{var}} pattern can't match). Unknown names
// resolve to '' so a missing capture never leaks the literal placeholder.
function substitute(str, { secrets = {}, vars = {} } = {}) {
  if (str == null) return str;
  return String(str)
    .replace(/\{\{\s*secret:([A-Za-z0-9_]{1,64})\s*\}\}/g, (_m, n) => (secrets[n] != null ? String(secrets[n]) : ''))
    .replace(/\{\{\s*([A-Za-z0-9_]{1,64})\s*\}\}/g, (_m, n) => (vars[n] != null ? String(vars[n]) : ''));
}

module.exports = { substitute };
