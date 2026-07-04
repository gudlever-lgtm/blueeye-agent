package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(Options{Env: map[string]string{}, BaseDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ServerURL != "http://localhost:3000" {
		t.Errorf("ServerURL = %q, want default", c.ServerURL)
	}
	if c.HeartbeatMs != 15000 || c.ReconnectBaseMs != 1000 || c.ReconnectMaxMs != 30000 {
		t.Errorf("tuning defaults wrong: %+v", c)
	}
	if c.ReportIntervalMs != 60000 || c.ReportSampleMs != 1000 {
		t.Errorf("report defaults wrong: %+v", c)
	}
	if !c.ProbeGateway || !c.ProbeDNS {
		t.Errorf("probe bool defaults should be true")
	}
	if c.TokenPath != filepath.Join(dir, ".blueeye-agent", "token") {
		t.Errorf("TokenPath = %q", c.TokenPath)
	}
}

func TestLoadFileThenEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "blueeye-agent.config.json")
	if err := os.WriteFile(cfg, []byte(`{"serverUrl":"https://from-file","heartbeatMs":9000,"probeGateway":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// File wins over default.
	c, _ := Load(Options{Env: map[string]string{"BLUEEYE_AGENT_CONFIG": cfg}, BaseDir: dir})
	if c.ServerURL != "https://from-file" || c.HeartbeatMs != 9000 || c.ProbeGateway {
		t.Fatalf("file values not applied: %+v", c)
	}
	// Env wins over file.
	c, _ = Load(Options{Env: map[string]string{
		"BLUEEYE_AGENT_CONFIG": cfg,
		"BLUEEYE_SERVER_URL":   "https://from-env",
		"BLUEEYE_HEARTBEAT_MS": "1234",
	}, BaseDir: dir})
	if c.ServerURL != "https://from-env" || c.HeartbeatMs != 1234 {
		t.Fatalf("env did not override file: %+v", c)
	}
}

func TestLoadInvalidFileErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(cfg, []byte("{not json"), 0o600)
	if _, err := Load(Options{Env: map[string]string{"BLUEEYE_AGENT_CONFIG": cfg}, BaseDir: dir}); err == nil {
		t.Fatal("expected error for invalid JSON config")
	}
}

func TestToBool(t *testing.T) {
	for _, tc := range []struct {
		in  string
		def bool
		out bool
	}{
		{"", true, true}, {"", false, false},
		{"0", true, false}, {"false", true, false}, {"NO", true, false}, {"Off", true, false},
		{"1", false, true}, {"true", false, true}, {"yes", false, true},
	} {
		if got := toBool(tc.in, tc.def); got != tc.out {
			t.Errorf("toBool(%q,%v) = %v, want %v", tc.in, tc.def, got, tc.out)
		}
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	full := "AB:CD:" + repeat("EF", 30) // 32 bytes
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"not-a-fp", ""},
		{"sha256:" + strip(full), full},
		{lower(strip(full)), full},
	} {
		if got := NormalizeFingerprint(tc.in); got != tc.want {
			t.Errorf("NormalizeFingerprint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ":" + s
	}
	return out[1:]
}
func strip(s string) string {
	out := ""
	for _, r := range s {
		if r != ':' {
			out += string(r)
		}
	}
	return out
}
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 32
		}
	}
	return string(b)
}
