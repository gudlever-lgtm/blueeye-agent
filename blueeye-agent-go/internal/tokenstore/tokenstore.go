// Package tokenstore reads and writes the agent credential exactly as the Node
// agent does (GO-REWRITE-AUDIT.md §5): a JSON document {agentId, token} — NOT a
// bare token string — persisted at mode 0600 with an explicit chmod after write.
package tokenstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Credentials is the on-disk credential shape. agentId may be null in the file;
// it is represented as a pointer so a missing/null value round-trips.
type Credentials struct {
	AgentID *int64 `json:"agentId"`
	Token   string `json:"token"`
}

// Read returns the stored credentials, or (nil, nil) when there is no usable
// token (missing file, unreadable, bad JSON, or empty token) — matching Node's
// readToken which returns null in all those cases.
func Read(path string) (*Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, nil // unreadable is treated as "not enrolled", like Node
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, nil
	}
	if c.Token == "" {
		return nil, nil
	}
	return &c, nil
}

// Save writes the credentials with owner-only permissions. It creates the parent
// directory and applies chmod 0600 explicitly (the file mode on create is not
// enough if the file already existed), matching Node's saveToken.
func Save(path string, c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
