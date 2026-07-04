package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
)

func TestInstallVersioning(t *testing.T) {
	s := NewStore(t.TempDir(), nil)
	d := validLinuxDef()

	if out, err := s.Install(d, SourceWebSocket); err != nil || out != Installed {
		t.Fatalf("first install: out=%s err=%v", out, err)
	}
	// Same version -> skipped.
	if out, err := s.Install(d, SourceWebSocket); err != nil || out != SkippedOlder {
		t.Fatalf("same-version install should skip: out=%s err=%v", out, err)
	}
	// Lower version -> skipped.
	lower := d
	lower.Version = 0 // invalid though; use a valid lower by bumping current first
	// Bump to v3, then try v2.
	d.Version = 3
	if out, _ := s.Install(d, SourceWebSocket); out != Replaced {
		t.Fatalf("v3 should replace, got %s", out)
	}
	older := d
	older.Version = 2
	if out, err := s.Install(older, SourceWebSocket); err != nil || out != SkippedOlder {
		t.Fatalf("older version should skip: out=%s err=%v", out, err)
	}
	if cur, _ := s.Get(d.ID); cur.Version != 3 {
		t.Fatalf("current version = %d, want 3", cur.Version)
	}
}

func TestInstallRejectsNonWebSocket(t *testing.T) {
	s := NewStore(t.TempDir(), nil)
	d := validLinuxDef()
	if _, err := s.Install(d, SourceREST); err != ErrUntrustedSource {
		t.Fatalf("REST source: err=%v, want ErrUntrustedSource", err)
	}
	if _, err := s.Install(d, SourceOther); err != ErrUntrustedSource {
		t.Fatalf("Other source: err=%v, want ErrUntrustedSource", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("rejected definition must not be stored")
	}
}

func TestInstallRejectsMalformed(t *testing.T) {
	s := NewStore(t.TempDir(), nil)
	bad := validLinuxDef()
	bad.Version = 0
	if _, err := s.Install(bad, SourceWebSocket); err == nil {
		t.Fatal("malformed definition should be rejected")
	}
}

func TestCacheRoundTripAndServerWins(t *testing.T) {
	dir := t.TempDir()
	s1 := NewStore(dir, nil)
	d := validLinuxDef()
	if _, err := s1.Install(d, SourceWebSocket); err != nil {
		t.Fatal(err)
	}
	// A fresh store loads the cached definition.
	s2 := NewStore(dir, nil)
	if err := s2.LoadCache(); err != nil {
		t.Fatal(err)
	}
	if got, ok := s2.Get(d.ID); !ok || got.Version != 1 {
		t.Fatalf("cache not loaded: %+v ok=%v", got, ok)
	}
	// Server (WebSocket) response with a higher version wins.
	d.Version = 5
	if out, _ := s2.Install(d, SourceWebSocket); out != Replaced {
		t.Fatalf("server response should replace cached, got %s", out)
	}
	if got, _ := s2.Get(d.ID); got.Version != 5 {
		t.Fatalf("server did not win: version=%d", got.Version)
	}
}

func TestLoadCacheSkipsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "note.txt"), []byte("ignore me"), 0o600)
	s := NewStore(dir, nil)
	if err := s.LoadCache(); err != nil {
		t.Fatalf("LoadCache should tolerate junk: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("no valid definitions expected")
	}
}

func TestInstallWritesTwoStateAudit(t *testing.T) {
	var records []audit.Record
	al := audit.New("", func(r audit.Record) { records = append(records, r) })
	s := NewStore(t.TempDir(), al)
	if _, err := s.Install(validLinuxDef(), SourceWebSocket); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 audit records (initiated, completed), got %d: %+v", len(records), records)
	}
	if records[0].State != audit.Initiated || records[1].State != audit.Completed {
		t.Fatalf("states = %s, %s; want initiated, completed", records[0].State, records[1].State)
	}
	if records[0].Action != "collector.install" {
		t.Fatalf("action = %s", records[0].Action)
	}
}
