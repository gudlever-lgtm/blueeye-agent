// Package report turns collector Results into the audited POST /agents/results
// envelope and sends them over the existing REST channel the live Node server
// already accepts and stores — so a Go agent exchanges data with a stock server
// without any server changes.
//
// For the network collectors (metrics net_rx_bytes/… with an iface label) it
// computes the per-interface delta + rate + totals, producing the SAME `traffic`
// snapshot shape as the Node proc/darwin/win samplers (the delta/rate stage that
// GO-REWRITE-AUDIT.md §8 flagged cannot live in a definition). Other collectors
// are sent as a generic metrics envelope (the server stores results as opaque
// JSON blobs, so both are accepted).
package report

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/apiclient"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/collector"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// trafficFields maps the net_* metric family to the Node traffic snapshot fields.
var trafficFields = map[string]string{
	"net_rx_bytes": "rxBytes", "net_rx_packets": "rxPackets", "net_rx_errors": "rxErrors", "net_rx_drop": "rxDrop",
	"net_tx_bytes": "txBytes", "net_tx_packets": "txPackets", "net_tx_errors": "txErrors", "net_tx_drop": "txDrop",
}

var rxFields = []string{"rxBytes", "txBytes", "rxPackets", "txPackets", "rxErrors", "txErrors", "rxDrop", "txDrop"}

// Assembler holds the previous cumulative counters per collector so it can turn
// successive raw-counter samples into deltas + rates. Concurrency-safe.
type Assembler struct {
	mu     sync.Mutex
	prev   map[string]map[string]map[string]int64 // collectorID -> iface -> field -> value
	prevTS map[string]time.Time
}

// NewAssembler builds an empty assembler.
func NewAssembler() *Assembler {
	return &Assembler{prev: map[string]map[string]map[string]int64{}, prevTS: map[string]time.Time{}}
}

func isTraffic(res collector.Result) bool {
	for _, s := range res.Samples {
		if strings.HasPrefix(s.Metric, "net_") {
			return true
		}
	}
	return false
}

// Envelope builds the results envelope for one collection cycle. Network
// collectors yield the `traffic` snapshot (deltas/rates); others yield a generic
// metrics envelope. shadow adds shadow:true.
func (a *Assembler) Envelope(res collector.Result, shadow bool, now time.Time) map[string]any {
	if isTraffic(res) {
		return a.trafficEnvelope(res, shadow, now)
	}
	return genericEnvelope(res, shadow)
}

func (a *Assembler) trafficEnvelope(res collector.Result, shadow bool, now time.Time) map[string]any {
	// Read the raw cumulative counters from this cycle's samples, grouped by iface.
	cur := map[string]map[string]int64{}
	for _, s := range res.Samples {
		field, ok := trafficFields[s.Metric]
		if !ok {
			continue
		}
		iface := s.Labels["iface"]
		if iface == "" {
			continue
		}
		if cur[iface] == nil {
			cur[iface] = map[string]int64{}
		}
		cur[iface][field] = int64(s.Value)
	}

	a.mu.Lock()
	prev := a.prev[res.DefinitionID]
	prevTS := a.prevTS[res.DefinitionID]
	a.prev[res.DefinitionID] = cur
	a.prevTS[res.DefinitionID] = now
	a.mu.Unlock()

	elapsed := 1.0
	if !prevTS.IsZero() {
		elapsed = math.Max(now.Sub(prevTS).Seconds(), 0.001)
	}

	ifaces := make([]string, 0, len(cur))
	for k := range cur {
		ifaces = append(ifaces, k)
	}
	sort.Strings(ifaces)

	totals := map[string]int64{}
	interfaces := make([]map[string]any, 0, len(ifaces))
	for _, iface := range ifaces {
		fields := cur[iface]
		var prevIface map[string]int64
		hadPrev := false
		if prev != nil {
			prevIface, hadPrev = prev[iface]
		}
		entry := map[string]any{"iface": iface, "operStatus": nil, "speedMbps": nil}
		for _, f := range rxFields {
			var delta int64
			if hadPrev && !prevTS.IsZero() {
				if d := fields[f] - prevIface[f]; d > 0 {
					delta = d
				}
			}
			entry[f] = delta
			totals[f] += delta
		}
		entry["rxBytesPerSec"] = round(float64(entry["rxBytes"].(int64)) / elapsed)
		entry["txBytesPerSec"] = round(float64(entry["txBytes"].(int64)) / elapsed)
		interfaces = append(interfaces, entry)
	}

	totalsOut := map[string]any{}
	for _, f := range rxFields {
		totalsOut[f] = totals[f]
	}
	totalsOut["rxBytesPerSec"] = round(float64(totals["rxBytes"]) / elapsed)
	totalsOut["txBytesPerSec"] = round(float64(totals["txBytes"]) / elapsed)

	traffic := map[string]any{
		"elapsedSec": math.Round(elapsed*1000) / 1000,
		"interfaces": interfaces,
		"totals":     totalsOut,
	}
	env := baseEnvelope("auto-report", res, shadow)
	env["traffic"] = traffic
	env["system"] = nil
	return env
}

func genericEnvelope(res collector.Result, shadow bool) map[string]any {
	env := baseEnvelope(res.DefinitionID, res, shadow)
	env["metrics"] = res.Samples
	env["system"] = nil
	return env
}

func baseEnvelope(name string, res collector.Result, shadow bool) map[string]any {
	env := map[string]any{
		"name":       name,
		"commandId":  nil,
		"ok":         true,
		"startedAt":  res.TS,
		"finishedAt": res.TS,
		"collector":  map[string]any{"id": res.DefinitionID, "version": res.Version},
	}
	if shadow {
		env["shadow"] = true
	}
	return env
}

func round(v float64) int64 { return int64(math.Round(v)) }

// Poster is the subset of the REST client the reporter needs.
type Poster interface {
	PostResults(ctx context.Context, results []any) error
}

// Reporter assembles envelopes and posts them to /agents/results.
type Reporter struct {
	api     Poster
	asm     *Assembler
	shadow  bool
	logger  *logx.Logger
	now     func() time.Time
	onFatal func()
}

// NewReporter builds a reporter. onFatal is invoked on a 401 (token rejected).
func NewReporter(api Poster, shadow bool, logger *logx.Logger, onFatal func()) *Reporter {
	if logger == nil {
		logger = logx.New(logx.Info)
	}
	return &Reporter{api: api, asm: NewAssembler(), shadow: shadow, logger: logger, now: time.Now, onFatal: onFatal}
}

// Report builds the envelope for a collection cycle and posts it. A 401 triggers
// onFatal; other errors are logged (non-fatal) and returned.
func (r *Reporter) Report(ctx context.Context, res collector.Result) error {
	env := r.asm.Envelope(res, r.shadow, r.now())
	if err := r.api.PostResults(ctx, []any{env}); err != nil {
		var ae *apiclient.Error
		if errors.As(err, &ae) && ae.Code == apiclient.TokenRejected {
			r.logger.Errorf("results POST rejected (401); token invalid")
			if r.onFatal != nil {
				r.onFatal()
			}
		} else {
			r.logger.Warnf("results POST failed (%s): %v", res.DefinitionID, err)
		}
		return err
	}
	r.logger.Debugf("posted results for %s (%d samples)", res.DefinitionID, len(res.Samples))
	return nil
}
