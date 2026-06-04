'use strict';

// Entry point used ONLY when the agent is packaged as a Single Executable
// Application (SEA) — see scripts/build-sea.sh.
//
// `src/index.js` exports main() and only self-starts under
// `require.main === module`. That guard isn't reliable inside a SEA (the
// injected main module isn't an ordinary module), so the packaged binary starts
// the agent explicitly here. Plain `node src/index.js …` and the test suite are
// unaffected — they never import this file.
//
// argv note: inside a SEA `process.argv` is `['<exe>', '<exe>', ...userArgs]`,
// i.e. the first user argument is at index 2 — the same offset as
// `node src/index.js …` — so the existing arg parsing in src/cli.js needs no
// changes. `blueeye-agent enroll --code …` therefore works as-is.

require('./index')
  .main()
  .catch((err) => {
    console.error(`Fatal: ${err && err.stack ? err.stack : err}`);
    process.exit(1);
  });
