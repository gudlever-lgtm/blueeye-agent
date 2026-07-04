package tokenstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "token")
	id := int64(42)
	if err := Save(p, Credentials{AgentID: &id, Token: "opaque-token"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got == nil || got.Token != "opaque-token" || got.AgentID == nil || *got.AgentID != 42 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestSavePermissions0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix perms")
	}
	p := filepath.Join(t.TempDir(), "token")
	if err := Save(p, Credentials{Token: "x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestReadMissingOrEmpty(t *testing.T) {
	dir := t.TempDir()
	// Missing file.
	if c, _ := Read(filepath.Join(dir, "nope")); c != nil {
		t.Errorf("missing file should read nil, got %+v", c)
	}
	// Empty token field.
	p := filepath.Join(dir, "empty")
	_ = os.WriteFile(p, []byte(`{"agentId":1,"token":""}`), 0o600)
	if c, _ := Read(p); c != nil {
		t.Errorf("empty token should read nil, got %+v", c)
	}
	// Bad JSON.
	p2 := filepath.Join(dir, "bad")
	_ = os.WriteFile(p2, []byte("garbage"), 0o600)
	if c, _ := Read(p2); c != nil {
		t.Errorf("bad json should read nil, got %+v", c)
	}
}

func TestReadNullAgentID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(p, []byte(`{"agentId":null,"token":"t"}`), 0o600)
	c, _ := Read(p)
	if c == nil || c.Token != "t" || c.AgentID != nil {
		t.Fatalf("null agentId case: %+v", c)
	}
}
