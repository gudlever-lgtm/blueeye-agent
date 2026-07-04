package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	out []byte
	err error
}

func (f fakeRunner) Run(_ context.Context, _ Exec, _ time.Duration, _ int) ([]byte, error) {
	return f.out, f.err
}

func newTestEngine(r ExecRunner, emit func(Result)) *Engine {
	return NewEngine(NewStore("", nil), r, nil, emit)
}

func sampleByMetricLabel(res Result, metric, labelKey, labelVal string) (Sample, bool) {
	for _, s := range res.Samples {
		if s.Metric == metric && s.Labels[labelKey] == labelVal {
			return s, true
		}
	}
	return Sample{}, false
}

// TestNetDevFieldForField loads the real linux.net_dev definition and verifies
// its output matches the Node agent's per-interface counter fields, with lo
// skipped and the interface colon trimmed.
func TestNetDevFieldForField(t *testing.T) {
	path := filepath.Join("..", "..", "collectors", "linux", "net_dev.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read def: %v", err)
	}
	var d Definition
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("unmarshal def: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("def invalid: %v", err)
	}

	canned := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo:   86519     111    0    0    0     0          0         0    86519     111    0    0    0     0       0          0\n" +
		"  eth0: 3259151   11051    0   22    0     0          0         0 27429535   11301    0    0    0     0       0          0\n"

	e := newTestEngine(fakeRunner{out: []byte(canned)}, nil)
	res, err := e.CollectOnce(context.Background(), d)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}

	// lo must be skipped.
	if _, ok := sampleByMetricLabel(res, "net_rx_bytes", "iface", "lo"); ok {
		t.Fatal("lo should be skipped by skip_line")
	}

	want := map[string]float64{
		"net_rx_bytes":   3259151,
		"net_rx_packets": 11051,
		"net_rx_errors":  0,
		"net_rx_drop":    22,
		"net_tx_bytes":   27429535,
		"net_tx_packets": 11301,
		"net_tx_errors":  0,
		"net_tx_drop":    0,
	}
	for metric, val := range want {
		s, ok := sampleByMetricLabel(res, metric, "iface", "eth0")
		if !ok {
			t.Errorf("missing sample %s{iface=eth0}", metric)
			continue
		}
		if s.Value != val {
			t.Errorf("%s{eth0} = %v, want %v", metric, s.Value, val)
		}
		if s.Type != Counter {
			t.Errorf("%s type = %s, want counter", metric, s.Type)
		}
	}
}

func TestOSRunnerTimeout(t *testing.T) {
	_, err := OSRunner{}.Run(context.Background(), Exec{Command: "sleep", Args: []string{"3"}}, 150*time.Millisecond, DefaultMaxOutput)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", err)
	}
}

func TestOSRunnerOversizedOutput(t *testing.T) {
	_, err := OSRunner{}.Run(context.Background(), Exec{Command: "head", Args: []string{"-c", "8192", "/dev/zero"}}, 5*time.Second, 1024)
	if err != ErrOversizedOutput {
		t.Fatalf("want ErrOversizedOutput, got %v", err)
	}
}

func TestOSRunnerRejectsPowerShell(t *testing.T) {
	_, err := OSRunner{}.Run(context.Background(), Exec{PowerShell: "Get-Date"}, time.Second, DefaultMaxOutput)
	if err != ErrPowerShellUnsupported {
		t.Fatalf("want ErrPowerShellUnsupported, got %v", err)
	}
}

func TestOSRunnerCommandFailure(t *testing.T) {
	_, err := OSRunner{}.Run(context.Background(), Exec{Command: "false"}, 5*time.Second, DefaultMaxOutput)
	if err == nil {
		t.Fatal("want error for non-zero exit")
	}
}

// TestFailingCollectorSkips ensures a collector whose exec errors never crashes
// the engine and never emits.
func TestFailingCollectorSkips(t *testing.T) {
	emitted := 0
	e := newTestEngine(fakeRunner{err: context.DeadlineExceeded}, func(Result) { emitted++ })
	// tick must not panic and must not emit.
	e.tick(context.Background(), validLinuxDef())
	if emitted != 0 {
		t.Fatalf("failing collector should not emit, emitted=%d", emitted)
	}
}

func TestCollectOnceMapsGaugesAndCounters(t *testing.T) {
	d := Definition{
		ID: "t", Version: 1, Platform: "linux", IntervalSeconds: 1,
		Exec:   Exec{Command: "true"},
		Parser: Parser{Type: ParserKeyValue},
		Output: Output{Metrics: []Metric{
			{Name: "g", Type: Gauge, Field: "g"},
			{Name: "c", Type: Counter, Field: "c"},
			{Name: "missing", Type: Gauge, Field: "nope"},
		}},
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(fakeRunner{out: []byte("g: 1.5\nc: 42\nother: text\n")}, nil)
	res, err := e.CollectOnce(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Samples) != 2 {
		t.Fatalf("want 2 samples (missing field skipped), got %d: %+v", len(res.Samples), res.Samples)
	}
	got := map[string]Sample{}
	for _, s := range res.Samples {
		got[s.Metric] = s
	}
	if got["g"].Value != 1.5 || got["g"].Type != Gauge {
		t.Errorf("gauge g = %+v", got["g"])
	}
	if got["c"].Value != 42 || got["c"].Type != Counter {
		t.Errorf("counter c = %+v", got["c"])
	}
}
