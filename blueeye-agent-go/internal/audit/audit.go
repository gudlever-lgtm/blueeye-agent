// Package audit writes two-state action records matching the Node agent's audit
// model (GO-REWRITE-AUDIT.md §4): every auditable action moves initiated ->
// completed|failed. Records are appended as JSON lines to a local file (0600),
// independent of the server, and an optional sink forwards them over the live
// channel. Best-effort: auditing never fails the action.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the lifecycle stage of an audited action.
type State string

const (
	// Initiated is written before the action's side effects begin.
	Initiated State = "initiated"
	// Completed is written after the action succeeds.
	Completed State = "completed"
	// Failed is written when the action errors.
	Failed State = "failed"
)

// Record is one audit line.
type Record struct {
	TS     string         `json:"ts"`
	Action string         `json:"action"`
	State  State          `json:"state"`
	Fields map[string]any `json:"fields,omitempty"`
}

// denied keys are never written in cleartext (mirrors Node's actionLog denylist).
var denied = map[string]bool{
	"token": true, "signature": true, "sig": true, "secret": true,
	"authorization": true, "password": true, "key": true,
}

// Logger appends audit records. The zero value is a no-op (path == "").
type Logger struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	sink func(Record)
}

// New returns an audit logger writing to path (empty = no-op). sink, if set,
// receives every record (e.g. to forward over WS); it must not block.
func New(path string, sink func(Record)) *Logger {
	return &Logger{path: path, now: time.Now, sink: sink}
}

func redact(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if denied[k] {
			out[k] = "[redacted]"
			continue
		}
		if s, ok := v.(string); ok && len(s) > 200 {
			out[k] = s[:200] + "…"
			continue
		}
		out[k] = v
	}
	return out
}

// Log writes one record (best-effort) and notifies the sink.
func (l *Logger) Log(action string, state State, fields map[string]any) {
	rec := Record{TS: l.now().UTC().Format(time.RFC3339), Action: action, State: state, Fields: redact(fields)}
	if l.sink != nil {
		func() {
			defer func() { _ = recover() }()
			l.sink(rec)
		}()
	}
	if l.path == "" {
		return
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(l.path), 0o700)
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// Action runs an initiated->completed/failed pair around fn. It writes Initiated
// first, then Completed on nil error or Failed (with the error detail) otherwise.
// The action's result is fn's error, unchanged.
func (l *Logger) Action(action string, fields map[string]any, fn func() error) error {
	l.Log(action, Initiated, fields)
	err := fn()
	if err != nil {
		ff := map[string]any{}
		for k, v := range fields {
			ff[k] = v
		}
		ff["error"] = err.Error()
		l.Log(action, Failed, ff)
		return err
	}
	l.Log(action, Completed, fields)
	return nil
}
