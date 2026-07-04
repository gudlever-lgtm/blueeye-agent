// Command blueeye-agent is the Go port of the BlueEye monitoring agent. This
// milestone wires config, token storage, the REST/WebSocket clients and the
// definition-driven collector engine. Collectors are DATA: the server pushes
// collector definitions over the authenticated WebSocket channel; the engine
// runs them sandboxed and emits metrics.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	builtins "github.com/gudlever-lgtm/blueeye-agent-go"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/apiclient"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/config"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/protocol"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/report"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/sflow"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/tokenstore"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/upgrade"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/wsclient"
)

// version is stamped at build time (-ldflags "-X main.version=...").
var version = "0.0.0-dev"

// nodePlatform/nodeArch map Go's runtime identifiers to the Node spellings the
// server expects (win32/x64), so the enrollment facts are byte-identical.
func nodePlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "win32"
	default:
		return runtime.GOOS
	}
}

func nodeArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	default:
		return runtime.GOARCH
	}
}

func main() {
	shadow := flag.Bool("shadow", false, "run as a shadow agent (tags hello + data with shadow:true)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load(config.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	cfg.Shadow = *shadow
	logger := logx.New(logx.ParseLevel(cfg.LogLevel))
	logger.Infof("BlueEye Go agent %s starting (%s/%s).", version, nodePlatform(), nodeArch())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Credentials: use the stored token, else enroll with the one-time code
	// (exchanged once for a permanent token). No token and no code is fatal.
	creds, err := ensureCredentials(ctx, cfg, logger)
	if err != nil {
		logger.Errorf("%v", err)
		os.Exit(1)
	}

	auditLog := audit.New(cfg.ActionLog, nil)
	api := apiclient.New(cfg.ServerURL, creds.Token, nil) // REST: results/config/capabilities

	// Definition precedence: bundled defaults (floor) < disk cache < server WS.
	// Seeding the built-ins means the agent has a working collector set — and
	// therefore data to report — against a stock server that pushes none.
	store := collector.NewStore(cfg.DefinitionsCacheDir, auditLog)
	store.Seed(builtins.Definitions())
	if err := store.LoadCache(); err != nil {
		logger.Warnf("collector cache load: %v", err)
	}
	logger.Infof("collector set: %d definition(s) (%d host-applicable).", len(store.List()), len(store.ListForHost()))

	// Reporter posts each collection cycle to /agents/results — the channel the
	// live server already ingests. A 401 there is fatal.
	reporter := report.NewReporter(api, cfg.Shadow, logger, func() { stop() })

	// The runner dispatches command execs to OSRunner and powershell bodies to a
	// persistent PowerShell stream (Windows). Close the stream on shutdown.
	runner := collector.DefaultRunner(logger)
	if sr, ok := runner.PS.(*collector.StreamRunner); ok {
		defer sr.Close()
	}
	engine := collector.NewEngine(store, runner, logger, func(res collector.Result) {
		_ = reporter.Report(ctx, res)
	})

	// Self-update: verified binary replacement (Ed25519, fail-closed). The
	// release trust anchor comes from BLUEEYE_RELEASE_PUBLIC_KEY; the collector
	// definitions cache (a separate dir) is never touched by an upgrade.
	releaseURL := fmt.Sprintf("%s/enroll/agent-binary?os=%s&arch=%s", cfg.ServerURL, runtime.GOOS, runtime.GOARCH)
	updater := upgrade.New(upgrade.Config{
		Download:  upgrade.HTTPDownloader(nil, releaseURL, creds.Token),
		Audit:     auditLog,
		PublicKey: upgrade.ResolveReleasePublicKey(os.Getenv),
		Restart:   upgrade.SystemdRestart(cfg.ServiceName),
		Logger:    logger,
	})

	// Declared before New so the handler closures can reference it.
	var ws *wsclient.Client
	ws = wsclient.New(wsclient.Options{
		Config: cfg,
		Token:  creds.Token,
		Logger: logger,
		Handlers: wsclient.Handlers{
			OnConnected: func(c protocol.Connected) {
				logger.Infof("connected as agent %d (server protocol v%d).", c.AgentID, c.ProtocolVersion)
				// On every (re)connect, report capabilities and fetch the
				// server-assigned config — the audited startup handshake.
				go func() {
					if err := api.PostCapabilities(ctx, buildCapabilities()); err != nil {
						logger.Warnf("report capabilities: %v", err)
					}
					if _, err := api.GetConfig(ctx); err != nil {
						logger.Warnf("fetch config: %v", err)
					}
					ws.RequestDefinitions()
				}()
			},
			OnCommand: func(raw json.RawMessage) {
				handleCommand(ctx, raw, updater, ws, logger)
			},
			OnDefinitions: func(raw json.RawMessage) {
				installDefinitions(raw, store, engine, ctx, logger)
			},
			OnFatal: func(reason string) {
				logger.Errorf("fatal: %s", reason)
				stop()
			},
		},
	})

	// sFlow: receive hsflowd datagrams on localhost:6343, decode locally, and
	// forward the flow summary to /agents/results (the channel the live server
	// ingests). Gated on BLUEEYE_SFLOW until monitorConfig-driven activation lands.
	if os.Getenv("BLUEEYE_SFLOW") != "" {
		coll := sflow.New(sflow.Options{BindAddress: "127.0.0.1", Port: 6343, Logger: logger})
		if err := coll.Start(ctx); err != nil {
			logger.Warnf("sflow collector: %v", err)
		} else {
			interval := time.Duration(cfg.ReportIntervalMs) * time.Millisecond
			restSend := func(v any) error { return api.PostResults(ctx, []any{v}) }
			fwd := sflow.NewForwarder(coll, restSend, interval, cfg.Shadow, logger)
			go fwd.Run(ctx)
		}
	}

	go engine.Run(ctx)
	go ws.Run(ctx)

	<-ctx.Done()
	logger.Infof("shutting down.")
}

// ensureCredentials returns usable credentials: the stored token if present,
// otherwise it enrolls with the one-time code and stores the issued token. No
// token and no code is a hard error (no retry) — like the Node agent.
func ensureCredentials(ctx context.Context, cfg config.Config, logger *logx.Logger) (*tokenstore.Credentials, error) {
	if c, _ := tokenstore.Read(cfg.TokenPath); c != nil {
		logger.Infof("using stored token (skipping enrollment).")
		return c, nil
	}
	if cfg.EnrollmentCode == "" {
		return nil, fmt.Errorf("no stored token at %s and no enrollment code — cannot enroll", cfg.TokenPath)
	}
	logger.Infof("no stored token; enrolling with the server...")
	hostname, _ := os.Hostname()
	res, err := apiclient.New(cfg.ServerURL, "", nil).Enroll(ctx, apiclient.EnrollRequest{
		Code: cfg.EnrollmentCode, Hostname: hostname, Platform: nodePlatform(), Arch: nodeArch(),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	creds := tokenstore.Credentials{AgentID: &res.AgentID, Token: res.Token}
	if err := tokenstore.Save(cfg.TokenPath, creds); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}
	logger.Infof("enrolled as agent %d; token stored at %s.", res.AgentID, cfg.TokenPath)
	return &creds, nil
}

// buildCapabilities reports what this agent can do, in the audited shape.
func buildCapabilities() map[string]any {
	sources := []string{"proc"}
	if os.Getenv("BLUEEYE_SFLOW") != "" {
		sources = append(sources, "sflow")
	}
	return map[string]any{
		"sources":      sources,
		"agentVersion": version,
		"managed":      detectManaged(),
	}
}

// detectManaged mirrors the Node agent's supervision detection.
func detectManaged() string {
	switch strings.ToLower(os.Getenv("BLUEEYE_RUNTIME")) {
	case "docker", "systemd", "unmanaged":
		return strings.ToLower(os.Getenv("BLUEEYE_RUNTIME"))
	}
	if _, err := os.Stat("/.dockerenv"); err == nil || os.Getenv("container") != "" {
		return "docker"
	}
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}
	return "unmanaged"
}

// updateVerbs recognises the update command aliases (matches command.js).
func isUpdateVerb(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "update", "self-update", "self_update", "selfupdate", "upgrade":
		return true
	}
	return false
}

// handleCommand dispatches a `command` frame. Only the update command is wired
// in this milestone; the rest are logged and ignored.
func handleCommand(ctx context.Context, raw json.RawMessage, updater *upgrade.Updater, ws *wsclient.Client, logger *logx.Logger) {
	var c struct {
		Name      string          `json:"name"`
		Action    string          `json:"action"`
		Type      string          `json:"type"`
		Command   string          `json:"command"`
		Version   string          `json:"version"`
		Signature string          `json:"signature"`
		ID        json.RawMessage `json:"id"`
		AuditID   json.RawMessage `json:"auditId"`
	}
	// The command may be a bare string or an object.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		c.Name = s
	} else {
		_ = json.Unmarshal(raw, &c)
	}
	verb := firstNonEmpty(c.Name, c.Action, c.Type, c.Command)
	if !isUpdateVerb(verb) {
		logger.Debugf("ignoring command %q (not wired in this build)", verb)
		return
	}
	_ = ws.Send(map[string]any{"type": "ack", "id": c.ID, "accepted": true, "runtime": "go"})
	if err := updater.Update(ctx, upgrade.Command{Version: c.Version, Signature: c.Signature}); err != nil {
		_ = ws.Send(map[string]any{"type": "action-result", "auditId": c.AuditID, "action": "upgrade", "ok": false, "detail": err.Error()})
		return
	}
	_ = ws.Send(map[string]any{"type": "action-result", "auditId": c.AuditID, "action": "upgrade", "ok": true, "version": c.Version})
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// installDefinitions applies a `definitions` frame (the ONLY trusted path) and
// reloads the engine. Malformed entries are logged and skipped.
func installDefinitions(raw json.RawMessage, store *collector.Store, engine *collector.Engine, ctx context.Context, logger *logx.Logger) {
	var frame struct {
		Definitions []collector.Definition `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		logger.Warnf("bad definitions frame: %v", err)
		return
	}
	changed := 0
	for _, d := range frame.Definitions {
		out, err := store.Install(d, collector.SourceWebSocket)
		if err != nil {
			logger.Warnf("reject definition %q: %v", d.ID, err)
			continue
		}
		if out != collector.SkippedOlder {
			changed++
			logger.Infof("collector %q %s (v%d).", d.ID, out, d.Version)
		}
	}
	if changed > 0 {
		engine.Reload(ctx)
	}
}
