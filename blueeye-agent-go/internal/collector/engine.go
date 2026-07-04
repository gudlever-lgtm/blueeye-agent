package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// Defaults for the exec sandbox.
const (
	DefaultTimeout   = 10 * time.Second
	DefaultMaxOutput = 1 << 20 // 1 MB
)

// ErrOversizedOutput is returned when a collector's stdout exceeds the cap.
var ErrOversizedOutput = errors.New("collector: output exceeded 1MB cap")

// ErrPowerShellUnsupported is returned when a windows/powershell definition is
// run by the generic runner. The persistent PowerShell stream (a later
// milestone) handles those; on Linux/darwin they simply don't apply.
var ErrPowerShellUnsupported = errors.New("collector: powershell exec requires the windows stream runner")

// Sample is one emitted metric point.
type Sample struct {
	Metric string            `json:"metric"`
	Type   MetricType        `json:"type"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Result is the output of one collection cycle.
type Result struct {
	DefinitionID string   `json:"definition_id"`
	Version      int      `json:"version"`
	TS           string   `json:"ts"`
	Samples      []Sample `json:"samples"`
}

// ExecRunner runs a definition's Exec and returns its stdout (capped). It is an
// interface so tests inject canned output without spawning processes, and so the
// windows PowerShell stream can plug in later.
type ExecRunner interface {
	Run(ctx context.Context, ex Exec, timeout time.Duration, maxOutput int) ([]byte, error)
}

// OSRunner runs exec.Command directly — no shell, args passed as an array, so
// server-provided strings are never interpolated into a shell.
type OSRunner struct{}

// Run executes the command with a timeout and caps stdout at maxOutput bytes.
func (OSRunner) Run(ctx context.Context, ex Exec, timeout time.Duration, maxOutput int) ([]byte, error) {
	if ex.PowerShell != "" {
		return nil, ErrPowerShellUnsupported
	}
	if ex.Command == "" {
		return nil, errors.New("collector: empty exec command")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// exec.CommandContext with an explicit args slice: no shell, nothing to
	// interpolate. The command name and args come from the definition verbatim.
	cmd := exec.CommandContext(cctx, ex.Command, ex.Args...)
	cw := &capWriter{limit: maxOutput}
	cmd.Stdout = cw
	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("collector: exec timed out after %s", timeout)
	}
	if cw.truncated {
		return nil, ErrOversizedOutput
	}
	if err != nil {
		return cw.buf, fmt.Errorf("collector: exec failed: %w", err)
	}
	return cw.buf, nil
}

// capWriter accumulates up to limit bytes, then flags truncation and drops the
// rest (without erroring the write, so the child process isn't killed by a
// broken pipe mid-flush).
type capWriter struct {
	buf       []byte
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if !w.truncated {
		room := w.limit - len(w.buf)
		if room <= 0 {
			w.truncated = true
		} else if len(p) > room {
			w.buf = append(w.buf, p[:room]...)
			w.truncated = true
		} else {
			w.buf = append(w.buf, p...)
		}
	}
	return len(p), nil
}

// Engine schedules collectors from a Store and emits Results. A failing
// collector logs and is skipped — it never crashes the agent.
type Engine struct {
	store     *Store
	runner    ExecRunner
	logger    *logx.Logger
	emit      func(Result)
	defTO     time.Duration
	maxOutput int
	now       func() time.Time

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// NewEngine builds an engine. runner defaults to OSRunner; emit is called with
// each successful collection Result (may be nil).
func NewEngine(store *Store, runner ExecRunner, logger *logx.Logger, emit func(Result)) *Engine {
	if runner == nil {
		runner = OSRunner{}
	}
	if logger == nil {
		logger = logx.New(logx.Info)
	}
	return &Engine{
		store: store, runner: runner, logger: logger, emit: emit,
		defTO: DefaultTimeout, maxOutput: DefaultMaxOutput, now: time.Now,
		running: map[string]context.CancelFunc{},
	}
}

// CollectOnce runs a single collection cycle for one definition: exec -> parse
// -> map to samples. Returns an error (never panics) so callers log-and-skip.
func (e *Engine) CollectOnce(ctx context.Context, d Definition) (Result, error) {
	timeout := e.defTO
	if d.Exec.TimeoutSeconds > 0 {
		timeout = time.Duration(d.Exec.TimeoutSeconds) * time.Second
	}
	out, err := e.runner.Run(ctx, d.Exec, timeout, e.maxOutput)
	if err != nil {
		return Result{}, err
	}
	rows, err := d.Parser.Parse(out)
	if err != nil {
		return Result{}, fmt.Errorf("parse: %w", err)
	}
	samples := mapRows(d, rows, e.logger)
	return Result{
		DefinitionID: d.ID,
		Version:      d.Version,
		TS:           e.now().UTC().Format(time.RFC3339),
		Samples:      samples,
	}, nil
}

// mapRows turns parsed rows into samples per the definition's Output. A metric
// whose value field is missing or non-numeric on a row is skipped (debug log),
// so a partially-parseable line still yields the metrics it can.
func mapRows(d Definition, rows []Row, logger *logx.Logger) []Sample {
	var samples []Sample
	for _, row := range rows {
		baseLabels := map[string]string{}
		for _, lf := range d.Output.LabelFields {
			if v, ok := row[lf]; ok {
				baseLabels[lf] = v
			}
		}
		for _, m := range d.Output.Metrics {
			raw, ok := row[m.Field]
			if !ok {
				continue
			}
			val, err := strconv.ParseFloat(raw, 64)
			if err != nil {
				logger.Debugf("collector %s: metric %s field %q not numeric (%q)", d.ID, m.Name, m.Field, raw)
				continue
			}
			labels := map[string]string{}
			for k, v := range baseLabels {
				labels[k] = v
			}
			for _, lf := range m.Labels {
				if v, ok := row[lf]; ok {
					labels[lf] = v
				}
			}
			if len(labels) == 0 {
				labels = nil
			}
			samples = append(samples, Sample{Metric: m.Name, Type: m.Type, Value: val, Labels: labels})
		}
	}
	return samples
}

// Run starts a scheduling loop: one goroutine per host-applicable definition,
// ticking at its interval. Reload() re-syncs goroutines to the current store.
// The loop exits when ctx is cancelled. A collector panic/error never escapes.
func (e *Engine) Run(ctx context.Context) {
	e.Reload(ctx)
	<-ctx.Done()
	e.mu.Lock()
	for _, cancel := range e.running {
		cancel()
	}
	e.running = map[string]context.CancelFunc{}
	e.mu.Unlock()
}

// Reload syncs running collector goroutines to the store's current
// host-applicable definitions: starts new ones, restarts changed ones, stops
// removed ones. Safe to call whenever definitions change.
func (e *Engine) Reload(ctx context.Context) {
	want := map[string]Definition{}
	for _, d := range e.store.ListForHost() {
		want[d.ID] = d
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Stop collectors no longer wanted.
	for id, cancel := range e.running {
		if _, ok := want[id]; !ok {
			cancel()
			delete(e.running, id)
		}
	}
	// Start collectors that aren't running yet.
	for id, d := range want {
		if _, ok := e.running[id]; ok {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		e.running[id] = cancel
		go e.loop(cctx, d)
	}
}

func (e *Engine) loop(ctx context.Context, d Definition) {
	interval := time.Duration(d.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	e.tick(ctx, d)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(ctx, d)
		}
	}
}

// tick runs one cycle, isolating panics so a bad collector can never crash the
// agent.
func (e *Engine) tick(ctx context.Context, d Definition) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Errorf("collector %s panicked (recovered): %v", d.ID, r)
		}
	}()
	res, err := e.CollectOnce(ctx, d)
	if err != nil {
		e.logger.Warnf("collector %s failed (skipping cycle): %v", d.ID, err)
		return
	}
	if e.emit != nil {
		e.emit(res)
	}
}
