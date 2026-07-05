// Package builtins is the module-root package. It embeds the default collector
// definitions shipped with the binary so the agent has a working collector set
// even before (or without) a server pushing definitions over the WebSocket
// channel. The server's live definitions still override these by version.
package builtins

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strings"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
)

//go:embed collectors/linux/*.json collectors/windows/*.json collectors/darwin/*.json
var definitionsFS embed.FS

// Definitions returns the bundled default collector definitions (all platforms).
// Invalid/unparseable entries are skipped defensively — the shipped files are
// validated by tests, so this should never drop a real one.
func Definitions() []collector.Definition {
	var out []collector.Definition
	_ = fs.WalkDir(definitionsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := definitionsFS.ReadFile(path)
		if err != nil {
			return nil
		}
		var def collector.Definition
		if json.Unmarshal(data, &def) != nil {
			return nil
		}
		if def.Validate() != nil {
			return nil
		}
		out = append(out, def)
		return nil
	})
	return out
}
