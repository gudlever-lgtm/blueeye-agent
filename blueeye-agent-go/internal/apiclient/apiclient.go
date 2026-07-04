// Package apiclient is the agent's REST client for Bearer-authenticated calls
// (GO-REWRITE-AUDIT.md §1.3). It handles status codes explicitly and never
// retries at the HTTP layer (the Node agent doesn't either — the next scheduled
// interval is the only retry). A 401 anywhere is fatal upstream.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Code classifies a failed call so callers can branch (esp. TokenRejected ->
// fatal). It mirrors the Node agent's coded errors.
type Code string

const (
	// TokenRejected is a 401 — fatal upstream (stop, do not reconnect/re-enroll).
	TokenRejected Code = "TOKEN_REJECTED"
	// NotFound is a 404.
	NotFound Code = "NOT_FOUND"
	// BadRequest is a 400 (validation).
	BadRequest Code = "BAD_REQUEST"
	// ServerError is a 5xx.
	ServerError Code = "SERVER_ERROR"
	// HTTPError is any other non-2xx.
	HTTPError Code = "HTTP_ERROR"
	// Transport is a connection/timeout error (no HTTP response).
	Transport Code = "TRANSPORT"
)

// Error carries the classification and the HTTP status (0 for transport errors).
type Error struct {
	Code   Code
	Status int
	Op     string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (HTTP %d): %v", e.Op, e.Code, e.Status, e.Err)
	}
	return fmt.Sprintf("%s: %s (HTTP %d)", e.Op, e.Code, e.Status)
}

// Unwrap exposes the underlying transport error.
func (e *Error) Unwrap() error { return e.Err }

// classify maps a status code to a Code. 200/201/2xx are success (nil).
func classify(status int) Code {
	switch {
	case status >= 200 && status < 300:
		return ""
	case status == 401:
		return TokenRejected
	case status == 400:
		return BadRequest
	case status == 404:
		return NotFound
	case status >= 500:
		return ServerError
	default:
		return HTTPError
	}
}

// Client is a Bearer-authenticated REST client bound to one server + token.
type Client struct {
	ServerURL string
	Token     string
	HTTP      *http.Client
}

// New returns a client with an explicit request timeout (the Node agent's
// pinned path uses 15s; we apply it to every call).
func New(serverURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{ServerURL: serverURL, Token: token, HTTP: hc}
}

// do performs one request, decoding a JSON response into out (may be nil). It
// classifies non-2xx responses into *Error and never retries.
func (c *Client) do(ctx context.Context, op, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return &Error{Code: HTTPError, Op: op, Err: err}
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.ServerURL+path, rdr)
	if err != nil {
		return &Error{Code: Transport, Op: op, Err: err}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return &Error{Code: Transport, Op: op, Err: err}
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if code := classify(res.StatusCode); code != "" {
		return &Error{Code: code, Status: res.StatusCode, Op: op}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		// Tolerate a non-JSON body like Node's jsonOrEmpty (best-effort decode).
		_ = json.Unmarshal(data, out)
	}
	return nil
}

// --- Request/response shapes (subset used so far) ---

// EnrollRequest is POST /agents/enroll (unauthenticated).
type EnrollRequest struct {
	Code     string `json:"code"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

// EnrollResponse is the 201 body.
type EnrollResponse struct {
	AgentID int64  `json:"agentId"`
	Token   string `json:"token"`
}

// Enroll performs the one-time enrollment. A non-201 is returned as *Error;
// callers do not retry (ENROLL_FAILED semantics).
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.do(ctx, "enroll", http.MethodPost, "/agents/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfigResponse is GET /agents/me/config.
type ConfigResponse struct {
	AgentID       int64           `json:"agentId"`
	MonitorConfig json.RawMessage `json:"monitorConfig"`
}

// GetConfig fetches the server-assigned monitor config.
func (c *Client) GetConfig(ctx context.Context) (*ConfigResponse, error) {
	var out ConfigResponse
	if err := c.do(ctx, "get config", http.MethodGet, "/agents/me/config", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostCapabilities reports capabilities + NIC inventory.
func (c *Client) PostCapabilities(ctx context.Context, capabilities any) error {
	return c.do(ctx, "report capabilities", http.MethodPost, "/agents/me/capabilities",
		map[string]any{"capabilities": capabilities}, nil)
}

// PostResults submits traffic/system measurements.
func (c *Client) PostResults(ctx context.Context, results []any) error {
	return c.do(ctx, "post results", http.MethodPost, "/agents/results",
		map[string]any{"results": results}, nil)
}

// PostProbeResults submits active-probe results.
func (c *Client) PostProbeResults(ctx context.Context, results []any) error {
	return c.do(ctx, "post probe results", http.MethodPost, "/agents/probe-results",
		map[string]any{"results": results}, nil)
}

// GetDefinitions fetches the current collector definitions over REST as a
// fallback/health path. The authoritative delivery is the WebSocket channel
// (definitions must only be *installed* from WS). Returns *Error on 404/500.
func (c *Client) GetDefinitions(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, "get definitions", http.MethodGet, "/agents/me/collectors", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
