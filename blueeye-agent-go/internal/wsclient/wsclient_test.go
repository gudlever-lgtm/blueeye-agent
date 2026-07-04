package wsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/config"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/protocol"
)

func TestToWsURL(t *testing.T) {
	if got := toWsURL("https://h:8443/base?x=1"); got != "wss://h:8443/ws/agent" {
		t.Errorf("https -> %q", got)
	}
	if got := toWsURL("http://h:3000"); got != "ws://h:3000/ws/agent" {
		t.Errorf("http -> %q", got)
	}
}

func TestHandshake401IsFatalNoReconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	fatalCh := make(chan string, 1)
	c := New(Options{
		Config:   config.Config{ServerURL: srv.URL, ReconnectBaseMs: 1, ReconnectMaxMs: 5, HeartbeatMs: 1000},
		Token:    "bad",
		Handlers: Handlers{OnFatal: func(reason string) { fatalCh <- reason }},
	})
	done := make(chan struct{})
	go func() { c.Run(context.Background()); close(done) }()

	select {
	case <-fatalCh:
	case <-time.After(2 * time.Second):
		t.Fatal("OnFatal not called on 401")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after fatal (it must not reconnect)")
	}
	if !c.isFatal() {
		t.Fatal("client should be fatal")
	}
}

func TestDefinitionsDeliveredOverWebSocket(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(protocol.HeaderProtocol) != "1" {
			t.Errorf("missing/incorrect X-BlueEye-Protocol header: %q", r.Header.Get(protocol.HeaderProtocol))
		}
		if r.Header.Get(protocol.HeaderAuthorization) != "Bearer tok" {
			t.Errorf("missing Bearer token: %q", r.Header.Get(protocol.HeaderAuthorization))
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "connected", "agentId": 9, "protocolVersion": 1})
		_ = conn.WriteJSON(map[string]any{
			"type":        "definitions",
			"definitions": []map[string]any{{"id": "linux.x", "version": 2}},
		})
		// Keep the connection open until the client closes it.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	connectedCh := make(chan protocol.Connected, 1)
	defsCh := make(chan json.RawMessage, 1)
	c := New(Options{
		Config: config.Config{ServerURL: srv.URL, ReconnectBaseMs: 1, ReconnectMaxMs: 5, HeartbeatMs: 1000},
		Token:  "tok",
		Handlers: Handlers{
			OnConnected:   func(m protocol.Connected) { connectedCh <- m },
			OnDefinitions: func(raw json.RawMessage) { defsCh <- raw },
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case m := <-connectedCh:
		if m.AgentID != 9 {
			t.Errorf("connected agentId = %d", m.AgentID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnected not called")
	}

	select {
	case raw := <-defsCh:
		var frame struct {
			Definitions []struct {
				ID      string `json:"id"`
				Version int    `json:"version"`
			} `json:"definitions"`
		}
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatalf("definitions frame: %v", err)
		}
		if len(frame.Definitions) != 1 || frame.Definitions[0].ID != "linux.x" || frame.Definitions[0].Version != 2 {
			t.Fatalf("unexpected definitions payload: %s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnDefinitions not called")
	}
}
