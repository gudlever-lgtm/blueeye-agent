package sflow

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// SendFunc forwards one frame over the live channel. It returns an error when
// the channel is down (not connected / write failed).
type SendFunc func(v any) error

// Frame is the WebSocket payload carrying a drained sFlow snapshot. The decoded
// snapshot shape is preserved verbatim under `data`; `shadow` tags a shadow
// deployment so server-side diffing can tell it from the Node agent.
type Frame struct {
	Type   string   `json:"type"`
	Kind   string   `json:"kind"`
	Shadow bool     `json:"shadow,omitempty"`
	Data   Snapshot `json:"data"`
}

// Forwarder periodically drains the collector and forwards the snapshot over the
// live channel. Backpressure: when the channel is down the snapshot is DROPPED
// (a counter increments); nothing is buffered unbounded.
type Forwarder struct {
	collector *Collector
	send      SendFunc
	interval  time.Duration
	shadow    bool
	logger    *logx.Logger

	forwarded    int64
	forwardDrops int64
}

// NewForwarder builds a forwarder. interval defaults to 60s.
func NewForwarder(c *Collector, send SendFunc, interval time.Duration, shadow bool, logger *logx.Logger) *Forwarder {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if logger == nil {
		logger = logx.New(logx.Info)
	}
	return &Forwarder{collector: c, send: send, interval: interval, shadow: shadow, logger: logger}
}

// Run drains + forwards on the interval until ctx is cancelled.
func (f *Forwarder) Run(ctx context.Context) {
	t := time.NewTicker(f.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.tick()
		}
	}
}

// tick drains one interval and forwards it (dropping on a down channel).
func (f *Forwarder) tick() {
	snap := f.collector.Drain()
	frame := Frame{Type: "data", Kind: "sflow", Shadow: f.shadow, Data: snap}
	if err := f.send(frame); err != nil {
		// Backpressure: the channel is down. Drop this snapshot and count it —
		// do NOT requeue or buffer, so memory stays flat while offline.
		atomic.AddInt64(&f.forwardDrops, 1)
		f.logger.Debugf("sFlow: channel down, dropped a flow snapshot (%v)", err)
		return
	}
	atomic.AddInt64(&f.forwarded, 1)
}

// Forwarded / ForwardDrops expose counters (for diagnose / tests).
func (f *Forwarder) Forwarded() int64    { return atomic.LoadInt64(&f.forwarded) }
func (f *Forwarder) ForwardDrops() int64 { return atomic.LoadInt64(&f.forwardDrops) }
