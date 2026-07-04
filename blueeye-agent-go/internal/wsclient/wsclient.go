// Package wsclient maintains the live WebSocket to /ws/agent (GO-REWRITE-AUDIT.md
// §1.4): it sends the Bearer token + X-BlueEye-Protocol in the upgrade headers,
// keeps an application heartbeat, dispatches inbound frames, and reconnects with
// the audited jittered backoff. A 401 handshake is fatal (no reconnect); a 403
// is retried with backoff.
package wsclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/backoff"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/config"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/protocol"
)

// Handlers receive dispatched inbound frames and lifecycle events.
type Handlers struct {
	// OnConnected fires after the server's `connected` frame.
	OnConnected func(protocol.Connected)
	// OnCommand fires for a `command` frame with the raw command value.
	OnCommand func(raw json.RawMessage)
	// OnDefinitions fires for a `definitions` frame with its raw payload. This is
	// the ONLY trusted path for collector definitions.
	OnDefinitions func(raw json.RawMessage)
	// OnFatal fires once on a terminal condition (401). The client will not
	// reconnect.
	OnFatal func(reason string)
}

// Options configures the client.
type Options struct {
	Config      config.Config
	Token       string
	Logger      *logx.Logger
	Handlers    Handlers
	DialTimeout time.Duration
}

// Client is a reconnecting WebSocket client.
type Client struct {
	opts    Options
	wsURL   string
	pin     string
	backoff backoff.Config

	mu    sync.Mutex
	conn  *websocket.Conn
	fatal bool
}

// New builds a client (does not connect).
func New(o Options) *Client {
	if o.Logger == nil {
		o.Logger = logx.New(logx.Info)
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 15 * time.Second
	}
	return &Client{
		opts:    o,
		wsURL:   toWsURL(o.Config.ServerURL),
		pin:     config.NormalizeFingerprint(o.Config.ServerCertFingerprint),
		backoff: backoff.Config{BaseMs: o.Config.ReconnectBaseMs, MaxMs: o.Config.ReconnectMaxMs, Factor: 2},
	}
}

// toWsURL derives ws(s)://host/ws/agent from the http(s) server URL.
func toWsURL(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/ws/agent"
	u.RawQuery = ""
	return u.String()
}

// Run connects and services the socket, reconnecting until ctx is cancelled or a
// fatal (401) occurs.
func (c *Client) Run(ctx context.Context) {
	attempt := 0
	for {
		if ctx.Err() != nil || c.isFatal() {
			return
		}
		err := c.connectAndServe(ctx)
		if c.isFatal() || ctx.Err() != nil {
			return
		}
		attempt++
		delay := backoff.Compute(attempt, c.backoff, nil)
		c.opts.Logger.Infof("WebSocket reconnect in %s (attempt %d): %v", delay, attempt, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = c.opts.DialTimeout
	if c.pin != "" && strings.HasPrefix(c.wsURL, "wss:") {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // we verify the exact leaf below
			VerifyConnection:   c.verifyPinned,
		}
	}
	header := http.Header{}
	header.Set(protocol.HeaderAuthorization, "Bearer "+c.opts.Token)
	header.Set(protocol.HeaderProtocol, fmt.Sprintf("%d", protocol.Version))

	conn, resp, err := dialer.DialContext(ctx, c.wsURL, header)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			c.setFatal("WebSocket authentication rejected (HTTP 401)")
			return err
		}
		if resp != nil {
			return fmt.Errorf("handshake HTTP %d: %w", resp.StatusCode, err)
		}
		return err
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.opts.Logger.Infof("WebSocket connection established.")

	hbCtx, stopHB := context.WithCancel(ctx)
	go c.heartbeat(hbCtx)
	defer stopHB()

	return c.readLoop(conn)
}

// verifyPinned accepts the connection only if the leaf cert's SHA-256 matches
// the configured pin (exact-leaf pinning, like the Node agent).
func (c *Client) verifyPinned(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificate")
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	got := hexColon(sum[:])
	if got != c.pin {
		return fmt.Errorf("certificate fingerprint mismatch (expected %s, got %s)", c.pin, got)
	}
	return nil
}

func hexColon(b []byte) string {
	const hexd = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*3)
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexd[x>>4], hexd[x&0x0f])
	}
	return string(out)
}

func (c *Client) readLoop(conn *websocket.Conn) error {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue // silently drop malformed frames, like the Node agent
		}
		switch env.Type {
		case protocol.FrameConnected:
			var m protocol.Connected
			if json.Unmarshal(data, &m) == nil && c.opts.Handlers.OnConnected != nil {
				if m.ProtocolVersion != 0 && m.ProtocolVersion != protocol.Version {
					c.opts.Logger.Warnf("server protocol v%d != agent v%d; continuing", m.ProtocolVersion, protocol.Version)
				}
				c.opts.Handlers.OnConnected(m)
			}
		case protocol.FrameCommand:
			var m struct {
				Command json.RawMessage `json:"command"`
			}
			if json.Unmarshal(data, &m) == nil && c.opts.Handlers.OnCommand != nil {
				c.opts.Handlers.OnCommand(m.Command)
			}
		case protocol.FrameDefinitions:
			if c.opts.Handlers.OnDefinitions != nil {
				c.opts.Handlers.OnDefinitions(data)
			}
		default:
			// Unknown frame types are ignored (both sides do this).
		}
	}
}

func (c *Client) heartbeat(ctx context.Context) {
	interval := time.Duration(c.opts.Config.HeartbeatMs) * time.Millisecond
	if interval <= 0 {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Send(protocol.Heartbeat{Type: protocol.FrameHeartbeat, TS: time.Now().UnixMilli()})
		}
	}
}

// Send writes a JSON frame if connected. Returns false when not connected.
func (c *Client) Send(v any) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return conn.WriteJSON(v)
}

// RequestDefinitions asks the server (over the live channel) for the current
// collector definitions. Best-effort: a closed socket just drops it.
func (c *Client) RequestDefinitions() {
	_ = c.Send(map[string]any{"type": protocol.FrameDefinitionsRequest})
}

func (c *Client) setFatal(reason string) {
	c.mu.Lock()
	already := c.fatal
	c.fatal = true
	conn := c.conn
	c.mu.Unlock()
	if already {
		return
	}
	c.opts.Logger.Errorf("Fatal: %s. The agent will NOT reconnect or re-enroll automatically.", reason)
	if conn != nil {
		_ = conn.Close()
	}
	if c.opts.Handlers.OnFatal != nil {
		c.opts.Handlers.OnFatal(reason)
	}
}

func (c *Client) isFatal() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fatal
}
