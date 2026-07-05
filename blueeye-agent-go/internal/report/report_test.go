package report

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/apiclient"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
)

func netResult(rxBytes, txBytes, rxPkts int64, ts string) collector.Result {
	lbl := map[string]string{"iface": "eth0"}
	return collector.Result{
		DefinitionID: "linux.net_dev", Version: 1, TS: ts,
		Samples: []collector.Sample{
			{Metric: "net_rx_bytes", Type: collector.Counter, Value: float64(rxBytes), Labels: lbl},
			{Metric: "net_tx_bytes", Type: collector.Counter, Value: float64(txBytes), Labels: lbl},
			{Metric: "net_rx_packets", Type: collector.Counter, Value: float64(rxPkts), Labels: lbl},
		},
	}
}

func TestTrafficDeltaAndRate(t *testing.T) {
	a := NewAssembler()
	t0 := time.Unix(1000, 0)
	t1 := t0.Add(2 * time.Second)

	// First cycle seeds; deltas are zero (no prior counters).
	env0 := a.Envelope(netResult(1000, 2000, 10, "t0"), false, t0)
	tr0 := env0["traffic"].(map[string]any)
	ifs0 := tr0["interfaces"].([]map[string]any)
	if len(ifs0) != 1 || ifs0[0]["rxBytes"].(int64) != 0 {
		t.Fatalf("first cycle should seed with zero deltas: %+v", ifs0)
	}

	// Second cycle 2s later: rx +500, tx +1000, pkts +40.
	env1 := a.Envelope(netResult(1500, 3000, 50, "t1"), false, t1)
	tr1 := env1["traffic"].(map[string]any)
	if env1["name"] != "auto-report" {
		t.Errorf("name = %v", env1["name"])
	}
	ifs1 := tr1["interfaces"].([]map[string]any)
	e := ifs1[0]
	if e["rxBytes"].(int64) != 500 || e["txBytes"].(int64) != 1000 || e["rxPackets"].(int64) != 40 {
		t.Errorf("deltas wrong: %+v", e)
	}
	// rates = delta / 2s.
	if e["rxBytesPerSec"].(int64) != 250 || e["txBytesPerSec"].(int64) != 500 {
		t.Errorf("rates wrong: rx=%v tx=%v", e["rxBytesPerSec"], e["txBytesPerSec"])
	}
	totals := tr1["totals"].(map[string]any)
	if totals["rxBytes"].(int64) != 500 || totals["rxBytesPerSec"].(int64) != 250 {
		t.Errorf("totals wrong: %+v", totals)
	}
	if tr1["elapsedSec"].(float64) != 2 {
		t.Errorf("elapsedSec = %v", tr1["elapsedSec"])
	}
}

func TestCounterResetClampedToZero(t *testing.T) {
	a := NewAssembler()
	t0 := time.Unix(1000, 0)
	a.Envelope(netResult(5000, 5000, 100, "t0"), false, t0)
	// Counter reset (values dropped): delta must clamp to 0, not go negative.
	env := a.Envelope(netResult(10, 10, 1, "t1"), false, t0.Add(time.Second))
	e := env["traffic"].(map[string]any)["interfaces"].([]map[string]any)[0]
	if e["rxBytes"].(int64) != 0 || e["txBytes"].(int64) != 0 {
		t.Errorf("counter reset should clamp to 0: %+v", e)
	}
}

func TestGenericEnvelopeAndShadow(t *testing.T) {
	a := NewAssembler()
	res := collector.Result{
		DefinitionID: "linux.loadavg", Version: 1, TS: "t",
		Samples: []collector.Sample{{Metric: "load1", Type: collector.Gauge, Value: 0.5}},
	}
	env := a.Envelope(res, true, time.Unix(0, 0))
	if env["name"] != "linux.loadavg" {
		t.Errorf("generic name = %v", env["name"])
	}
	if _, ok := env["traffic"]; ok {
		t.Error("generic result should not have a traffic field")
	}
	if env["shadow"] != true {
		t.Error("shadow flag not set")
	}
	if _, ok := env["metrics"]; !ok {
		t.Error("generic result should carry metrics")
	}
}

type fakePoster struct {
	posted [][]any
	err    error
}

func (f *fakePoster) PostResults(_ context.Context, results []any) error {
	if f.err != nil {
		return f.err
	}
	f.posted = append(f.posted, results)
	return nil
}

func TestReporterPostsAndHandles401(t *testing.T) {
	fp := &fakePoster{}
	r := NewReporter(fp, false, nil, nil)
	if err := r.Report(context.Background(), netResult(1, 1, 1, "t")); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if len(fp.posted) != 1 || len(fp.posted[0]) != 1 {
		t.Fatalf("expected one posted envelope, got %+v", fp.posted)
	}

	// 401 -> onFatal fires.
	fatal := false
	r401 := NewReporter(&fakePoster{err: &apiclient.Error{Code: apiclient.TokenRejected, Status: 401}}, false, nil, func() { fatal = true })
	if err := r401.Report(context.Background(), netResult(1, 1, 1, "t")); err == nil {
		t.Fatal("expected error on 401")
	}
	if !fatal {
		t.Error("onFatal should fire on 401")
	}

	// Non-401 error -> returned, no fatal.
	fatal2 := false
	rErr := NewReporter(&fakePoster{err: errors.New("boom")}, false, nil, func() { fatal2 = true })
	if err := rErr.Report(context.Background(), netResult(1, 1, 1, "t")); err == nil {
		t.Fatal("expected error")
	}
	if fatal2 {
		t.Error("non-401 must not trigger fatal")
	}
}
