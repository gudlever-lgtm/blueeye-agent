// Package e2e drives the real REST + WebSocket + collector + reporter stack
// against a contract-faithful stub server (the same endpoints the live
// blueeye-server exposes) to prove the Go agent actually exchanges data end to
// end: enroll → WS connect → capabilities → config → results POST, plus the
// 401-fatal path.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	builtins "github.com/gudlever-lgtm/blueeye-agent-go"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/apiclient"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/config"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/protocol"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/report"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/wsclient"
)

// stub is a minimal, contract-faithful blueeye-server: the agent-facing REST
// endpoints + the /ws/agent upgrade, recording what it receives.
type stub struct {
	srv *httptest.Server

	mu           sync.Mutex
	capsAuth     string
	resultsAuth  string
	resultsBody  []map[string]any
	wsAuth       string
	wsProto      string
	forceResults int // if non-zero, /agents/results returns this status
}

func newStub() *stub {
	s := &stub{}
	up := websocket.Upgrader{}
	mux := http.NewServeMux()

	mux.HandleFunc("/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["code"] == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"agentId": 7, "token": "issued-token"})
	})

	mux.HandleFunc("/agents/me/capabilities", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.capsAuth = r.Header.Get("Authorization")
		s.mu.Unlock()
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{"agentId": 7})
	})

	mux.HandleFunc("/agents/me/config", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{"agentId": 7, "monitorConfig": map[string]any{"source": "proc"}})
	})

	mux.HandleFunc("/agents/results", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		force := s.forceResults
		s.mu.Unlock()
		if force != 0 {
			w.WriteHeader(force)
			return
		}
		data, _ := io.ReadAll(r.Body)
		var body struct {
			Results []map[string]any `json:"results"`
		}
		_ = json.Unmarshal(data, &body)
		// Enforce the server's per-result 64 KiB cap.
		for _, res := range body.Results {
			b, _ := json.Marshal(res)
			if len(b) > 65535 {
				w.WriteHeader(400)
				return
			}
		}
		s.mu.Lock()
		s.resultsAuth = r.Header.Get("Authorization")
		s.resultsBody = append(s.resultsBody, body.Results...)
		s.mu.Unlock()
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"inserted": len(body.Results)})
	})

	mux.HandleFunc("/ws/agent", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.wsAuth = r.Header.Get(protocol.HeaderAuthorization)
		s.wsProto = r.Header.Get(protocol.HeaderProtocol)
		s.mu.Unlock()
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "connected", "agentId": 7, "protocolVersion": 1})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	s.srv = httptest.NewServer(mux)
	return s
}

func (s *stub) close() { s.srv.Close() }

// cannedRunner returns pre-baked stdout per successive call (last one repeats).
type cannedRunner struct {
	outs [][]byte
	i    int
}

func (c *cannedRunner) Run(_ context.Context, _ collector.Exec, _ time.Duration, _ int) ([]byte, error) {
	o := c.outs[min(c.i, len(c.outs)-1)]
	c.i++
	return o, nil
}

func netDevDef(t *testing.T) collector.Definition {
	for _, d := range builtins.Definitions() {
		if d.ID == "linux.net_dev" {
			return d
		}
	}
	t.Fatal("linux.net_dev not found in embedded definitions")
	return collector.Definition{}
}

func procNetDev(rxBytes, txBytes int) string {
	return "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo:   86519     111    0    0    0     0          0         0    86519     111    0    0    0     0       0          0\n" +
		fmtEth(rxBytes, txBytes)
}

func fmtEth(rx, tx int) string {
	// eth0: rx=<rx> rxpkts=10 0 0 0 0 0 0 tx=<tx> txpkts=20 0 0 0 0 0 0
	return "  eth0: " +
		itoa(rx) + "   10    0    0    0     0          0         0 " +
		itoa(tx) + "   20    0    0    0     0       0          0\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestEndToEndDataExchange runs the whole loop against the stub and asserts the
// server receives a well-formed traffic results POST it accepts (201).
func TestEndToEndDataExchange(t *testing.T) {
	st := newStub()
	defer st.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1) Enroll (unauthenticated) → token.
	enrollClient := apiclient.New(st.srv.URL, "", st.srv.Client())
	enr, err := enrollClient.Enroll(ctx, apiclient.EnrollRequest{Code: "one-time", Hostname: "h1", Platform: "linux", Arch: "x64"})
	if err != nil || enr.Token != "issued-token" {
		t.Fatalf("enroll: %v (%+v)", err, enr)
	}

	api := apiclient.New(st.srv.URL, enr.Token, st.srv.Client())

	// 2) Capabilities + config handshake.
	if err := api.PostCapabilities(ctx, map[string]any{"sources": []string{"proc"}, "agentVersion": "test", "managed": "unmanaged"}); err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	mc, err := api.GetConfig(ctx)
	if err != nil || string(mc.MonitorConfig) == "" {
		t.Fatalf("config: %v (%+v)", err, mc)
	}

	// 3) WebSocket connect — assert the upgrade carried the Bearer + protocol header.
	cfg := config.Config{ServerURL: st.srv.URL, ReconnectBaseMs: 1, ReconnectMaxMs: 5, HeartbeatMs: 1000}
	connected := make(chan struct{}, 1)
	ws := wsclient.New(wsclient.Options{
		Config: cfg, Token: enr.Token,
		Handlers: wsclient.Handlers{OnConnected: func(protocol.Connected) { connected <- struct{}{} }},
	})
	go ws.Run(ctx)
	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("WebSocket never connected")
	}

	// 4) Collect two cycles and report each — the second carries real deltas.
	def := netDevDef(t)
	runner := &cannedRunner{outs: [][]byte{[]byte(procNetDev(1000, 2000)), []byte(procNetDev(1500, 3000))}}
	reporter := report.NewReporter(api, false, nil, nil)
	engine := collector.NewEngine(collector.NewStore("", nil), runner, nil, func(res collector.Result) {
		if err := reporter.Report(ctx, res); err != nil {
			t.Errorf("report: %v", err)
		}
	})
	for i := 0; i < 2; i++ {
		res, err := engine.CollectOnce(ctx, def)
		if err != nil {
			t.Fatalf("collect %d: %v", i, err)
		}
		if err := reporter.Report(ctx, res); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}

	// 5) Assert the stub received well-formed, authenticated traffic data.
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.wsAuth != "Bearer issued-token" || st.wsProto != "1" {
		t.Errorf("ws upgrade headers = %q / %q", st.wsAuth, st.wsProto)
	}
	if st.capsAuth != "Bearer issued-token" || st.resultsAuth != "Bearer issued-token" {
		t.Errorf("auth headers caps=%q results=%q", st.capsAuth, st.resultsAuth)
	}
	if len(st.resultsBody) != 2 {
		t.Fatalf("server received %d results, want 2", len(st.resultsBody))
	}
	// The second result must carry the traffic snapshot with the eth0 delta.
	second := st.resultsBody[1]
	if second["name"] != "auto-report" {
		t.Errorf("result name = %v", second["name"])
	}
	traffic, ok := second["traffic"].(map[string]any)
	if !ok {
		t.Fatalf("second result has no traffic snapshot: %+v", second)
	}
	ifaces, ok := traffic["interfaces"].([]any)
	if !ok || len(ifaces) != 1 {
		t.Fatalf("interfaces = %+v", traffic["interfaces"])
	}
	eth0 := ifaces[0].(map[string]any)
	if eth0["iface"] != "eth0" {
		t.Errorf("iface = %v", eth0["iface"])
	}
	if rx, _ := eth0["rxBytes"].(float64); rx != 500 {
		t.Errorf("eth0 rxBytes delta = %v, want 500", eth0["rxBytes"])
	}
	if tx, _ := eth0["txBytes"].(float64); tx != 1000 {
		t.Errorf("eth0 txBytes delta = %v, want 1000", eth0["txBytes"])
	}
}

// TestResults401IsFatal verifies a 401 on the results POST trips the reporter's
// fatal callback (the agent must stop, not spin).
func TestResults401IsFatal(t *testing.T) {
	st := newStub()
	defer st.close()
	st.mu.Lock()
	st.forceResults = 401
	st.mu.Unlock()

	api := apiclient.New(st.srv.URL, "bad-token", st.srv.Client())
	fatal := make(chan struct{}, 1)
	reporter := report.NewReporter(api, false, nil, func() { fatal <- struct{}{} })

	def := netDevDef(t)
	runner := &cannedRunner{outs: [][]byte{[]byte(procNetDev(1, 1))}}
	engine := collector.NewEngine(collector.NewStore("", nil), runner, nil, nil)
	res, err := engine.CollectOnce(context.Background(), def)
	if err != nil {
		t.Fatal(err)
	}
	_ = reporter.Report(context.Background(), res)
	select {
	case <-fatal:
	case <-time.After(time.Second):
		t.Fatal("401 on results POST did not trigger the fatal callback")
	}
}
