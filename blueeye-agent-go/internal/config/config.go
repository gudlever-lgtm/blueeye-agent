// Package config loads agent configuration with the Node agent's precedence
// (GO-REWRITE-AUDIT.md §6): built-in defaults < JSON config file < environment.
// Paths default relative to the executable's own directory, never the current
// working directory, so a service started from a different cwd (or a deleted
// cwd after uninstall) still resolves the same files.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the resolved agent configuration.
type Config struct {
	ConfigPath            string
	ServerURL             string
	EnrollmentCode        string
	ServerCertFingerprint string
	TokenPath             string
	HeartbeatMs           int
	ReconnectBaseMs       int
	ReconnectMaxMs        int
	ReportIntervalMs      int
	ReportSampleMs        int
	ProbeIntervalMs       int
	ProbeCount            int
	ProbeGateway          bool
	ProbeDNS              bool
	ProbeTargets          []string
	LogLevel              string
	ActionLog             string
	ServiceName           string
	Runtime               string // "", "systemd", "docker", "unmanaged"
	ReleasePublicKey      string
	// DefinitionsCacheDir is where received collector definitions are cached on
	// disk (Go-agent extension). Defaults next to the token.
	DefinitionsCacheDir string
	// Shadow marks this agent as a shadow deployment (Go-agent extension): it
	// runs normally but tags its hello/registration and every data message with
	// shadow:true so server-side diffing can tell it apart from the Node agent.
	Shadow bool
}

// fileConfig is the on-disk JSON shape (matches config.example.json keys).
type fileConfig struct {
	ServerURL             *string         `json:"serverUrl"`
	EnrollmentCode        *string         `json:"enrollmentCode"`
	ServerCertFingerprint *string         `json:"serverCertFingerprint"`
	TokenPath             *string         `json:"tokenPath"`
	HeartbeatMs           *int            `json:"heartbeatMs"`
	ReconnectBaseMs       *int            `json:"reconnectBaseMs"`
	ReconnectMaxMs        *int            `json:"reconnectMaxMs"`
	ReportIntervalMs      *int            `json:"reportIntervalMs"`
	ReportSampleMs        *int            `json:"reportSampleMs"`
	ProbeIntervalMs       *int            `json:"probeIntervalMs"`
	ProbeCount            *int            `json:"probeCount"`
	ProbeGateway          *bool           `json:"probeGateway"`
	ProbeDNS              *bool           `json:"probeDns"`
	ProbeTargets          json.RawMessage `json:"probeTargets"`
	DefinitionsCacheDir   *string         `json:"definitionsCacheDir"`
}

// Options controls Load. Env and BaseDir are injectable for tests.
type Options struct {
	Env     map[string]string // if nil, os.Environ() is used
	BaseDir string            // if empty, the executable's directory is used
}

func env(o Options, key string) (string, bool) {
	if o.Env != nil {
		v, ok := o.Env[key]
		return v, ok
	}
	return os.LookupEnv(key)
}

func envOr(o Options, key, def string) string {
	if v, ok := env(o, key); ok && v != "" {
		return v
	}
	return def
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// toBool mirrors Node's toBool: false only for 0/false/no/off (case-insensitive).
func toBool(s string, def bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return def
	}
	switch s {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func baseDir(o Options) string {
	if o.BaseDir != "" {
		return o.BaseDir
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

// Load resolves the configuration. It never returns an error for a missing
// config file (that is normal); it only errors if a present file is invalid JSON.
func Load(o Options) (Config, error) {
	bd := baseDir(o)
	cfgPath := envOr(o, "BLUEEYE_AGENT_CONFIG", filepath.Join(bd, "blueeye-agent.config.json"))

	var fc fileConfig
	if data, err := os.ReadFile(cfgPath); err == nil {
		if len(strings.TrimSpace(string(data))) > 0 {
			if err := json.Unmarshal(data, &fc); err != nil {
				return Config{}, err
			}
		}
	}

	str := func(envKey string, file *string, def string) string {
		if v, ok := env(o, envKey); ok && v != "" {
			return v
		}
		if file != nil && *file != "" {
			return *file
		}
		return def
	}
	intv := func(envKey string, file *int, def int) int {
		if v, ok := env(o, envKey); ok && v != "" {
			return atoiOr(v, def)
		}
		if file != nil {
			return *file
		}
		return def
	}
	boolv := func(envKey string, file *bool, def bool) bool {
		if v, ok := env(o, envKey); ok && v != "" {
			return toBool(v, def)
		}
		if file != nil {
			return *file
		}
		return def
	}

	c := Config{
		ConfigPath:            cfgPath,
		ServerURL:             str("BLUEEYE_SERVER_URL", fc.ServerURL, "http://localhost:3000"),
		EnrollmentCode:        str("BLUEEYE_ENROLLMENT_CODE", fc.EnrollmentCode, ""),
		ServerCertFingerprint: NormalizeFingerprint(str("BLUEEYE_SERVER_CERT_FINGERPRINT", fc.ServerCertFingerprint, "")),
		TokenPath:             str("BLUEEYE_TOKEN_PATH", fc.TokenPath, filepath.Join(bd, ".blueeye-agent", "token")),
		HeartbeatMs:           intv("BLUEEYE_HEARTBEAT_MS", fc.HeartbeatMs, 15000),
		ReconnectBaseMs:       intv("BLUEEYE_RECONNECT_BASE_MS", fc.ReconnectBaseMs, 1000),
		ReconnectMaxMs:        intv("BLUEEYE_RECONNECT_MAX_MS", fc.ReconnectMaxMs, 30000),
		ReportIntervalMs:      intv("BLUEEYE_REPORT_INTERVAL_MS", fc.ReportIntervalMs, 60000),
		ReportSampleMs:        intv("BLUEEYE_REPORT_SAMPLE_MS", fc.ReportSampleMs, 1000),
		ProbeIntervalMs:       intv("BLUEEYE_PROBE_INTERVAL_MS", fc.ProbeIntervalMs, 60000),
		ProbeCount:            intv("BLUEEYE_PROBE_COUNT", fc.ProbeCount, 3),
		ProbeGateway:          boolv("BLUEEYE_PROBE_GATEWAY", fc.ProbeGateway, true),
		ProbeDNS:              boolv("BLUEEYE_PROBE_DNS", fc.ProbeDNS, true),
		ProbeTargets:          parseTargets(o, fc.ProbeTargets),
		LogLevel:              envOr(o, "BLUEEYE_LOG_LEVEL", "info"),
		ActionLog:             envOr(o, "BLUEEYE_ACTION_LOG", ""),
		ServiceName:           envOr(o, "BLUEEYE_SERVICE_NAME", "blueeye-agent"),
		Runtime:               strings.ToLower(envOr(o, "BLUEEYE_RUNTIME", "")),
		ReleasePublicKey:      envOr(o, "BLUEEYE_RELEASE_PUBLIC_KEY", ""),
	}
	c.DefinitionsCacheDir = str("BLUEEYE_DEFINITIONS_DIR", fc.DefinitionsCacheDir,
		filepath.Join(filepath.Dir(c.TokenPath), "definitions"))
	return c, nil
}

// parseTargets accepts BLUEEYE_PROBE_TARGETS (comma string) or the file's
// probeTargets (array or comma string) and returns raw spec strings. Full
// spec parsing lives in the probes package (out of scope here).
func parseTargets(o Options, fileRaw json.RawMessage) []string {
	if v, ok := env(o, "BLUEEYE_PROBE_TARGETS"); ok && v != "" {
		return splitComma(v)
	}
	if len(fileRaw) > 0 {
		var arr []string
		if err := json.Unmarshal(fileRaw, &arr); err == nil {
			return arr
		}
		var s string
		if err := json.Unmarshal(fileRaw, &s); err == nil {
			return splitComma(s)
		}
	}
	return []string{}
}

func splitComma(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
