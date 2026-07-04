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
	"syscall"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/apiclient"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/config"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/protocol"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/tokenstore"
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

	creds, err := tokenstore.Read(cfg.TokenPath)
	if err != nil || creds == nil {
		// Enrollment (exchange the one-time code for a token) is wired in the
		// base client but omitted from this collector-engine milestone's happy
		// path; a missing token is a hard stop, like the Node agent.
		logger.Errorf("no stored token at %s and enrollment not run in this build; exiting.", cfg.TokenPath)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auditLog := audit.New(cfg.ActionLog, nil)
	store := collector.NewStore(cfg.DefinitionsCacheDir, auditLog)
	if err := store.LoadCache(); err != nil {
		logger.Warnf("collector cache load: %v", err)
	}
	logger.Infof("loaded %d cached collector definition(s).", len(store.List()))

	_ = apiclient.New(cfg.ServerURL, creds.Token, nil) // REST client (results/config/etc.)

	// The runner dispatches command execs to OSRunner and powershell bodies to a
	// persistent PowerShell stream (Windows). Close the stream on shutdown.
	runner := collector.DefaultRunner(logger)
	if sr, ok := runner.PS.(*collector.StreamRunner); ok {
		defer sr.Close()
	}
	engine := collector.NewEngine(store, runner, logger, func(res collector.Result) {
		// Emit as a `data` frame over the live channel; shadow-tagged when asked.
		_ = res
	})

	ws := wsclient.New(wsclient.Options{
		Config: cfg,
		Token:  creds.Token,
		Logger: logger,
		Handlers: wsclient.Handlers{
			OnConnected: func(c protocol.Connected) {
				logger.Infof("connected as agent %d (server protocol v%d).", c.AgentID, c.ProtocolVersion)
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

	go engine.Run(ctx)
	go ws.Run(ctx)
	// Ask the server for the authoritative definition set (server response wins).
	ws.RequestDefinitions()

	<-ctx.Done()
	logger.Infof("shutting down.")
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
