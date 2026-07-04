package sflow

import (
	"context"
	"errors"
	"testing"
)

func TestCollectorFeedAndDrain(t *testing.T) {
	c := New(Options{})
	pkt := rawPacketIPv4TCP([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 1000, 443, 6)
	c.Feed(flowSampleDatagram(10, 200, pkt))
	c.Feed([]byte{0x00, 0x01}) // malformed -> dropped
	c.Feed(counterSampleDatagram())

	st := c.Stats()
	if st.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", st.Dropped)
	}
	if st.CounterSamples != 1 {
		t.Errorf("counterSamples = %d, want 1", st.CounterSamples)
	}
	if st.BufferedFlows != 1 {
		t.Errorf("bufferedFlows = %d, want 1", st.BufferedFlows)
	}

	snap := c.Drain()
	if snap.Source != "sflow" || !snap.Sampled {
		t.Errorf("snapshot header = %+v", snap)
	}
	if snap.Datagrams != 2 { // flow + counter decoded OK; malformed excluded
		t.Errorf("datagrams = %d, want 2", snap.Datagrams)
	}
	if snap.DroppedDatagrams != 1 {
		t.Errorf("droppedDatagrams = %d, want 1", snap.DroppedDatagrams)
	}
	if snap.Totals.Bytes != 200*10 || snap.Totals.Flows != 1 {
		t.Errorf("totals = %+v", snap.Totals)
	}
	if len(snap.ByPort) != 1 || snap.ByPort[0].Port != 443 {
		t.Errorf("byPort = %+v", snap.ByPort)
	}
	if len(snap.ByProtocol) != 1 || snap.ByProtocol[0].Protocol != "tcp" {
		t.Errorf("byProtocol = %+v", snap.ByProtocol)
	}
	if len(snap.TopTalkers) != 1 || snap.TopTalkers[0].Pair != "10.0.0.1->8.8.8.8" {
		t.Errorf("topTalkers = %+v", snap.TopTalkers)
	}

	// Drain cleared the buffer.
	if c.Stats().BufferedFlows != 0 {
		t.Error("buffer not cleared after drain")
	}
}

func TestCollectorBufferBounded(t *testing.T) {
	c := New(Options{MaxFlows: 2})
	pkt := rawPacketIPv4TCP([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, 6)
	// A datagram with one flow each; feed 5 -> buffer caps at 2, 3 overflow.
	for i := 0; i < 5; i++ {
		c.Feed(flowSampleDatagram(1, 100, pkt))
	}
	st := c.Stats()
	if st.BufferedFlows != 2 {
		t.Errorf("bufferedFlows = %d, want 2 (bounded)", st.BufferedFlows)
	}
	if st.BufferOverflow != 3 {
		t.Errorf("bufferOverflow = %d, want 3", st.BufferOverflow)
	}
}

func TestForwarderBackpressure(t *testing.T) {
	c := New(Options{})
	pkt := rawPacketIPv4TCP([4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, 6)
	c.Feed(flowSampleDatagram(1, 100, pkt))

	// Channel down: send returns an error -> snapshot dropped, counter++.
	down := NewForwarder(c, func(any) error { return errors.New("not connected") }, 0, false, nil)
	down.tick()
	if down.ForwardDrops() != 1 || down.Forwarded() != 0 {
		t.Fatalf("down channel: drops=%d forwarded=%d, want 1/0", down.ForwardDrops(), down.Forwarded())
	}
	// The drop must not requeue: the buffer was already drained (bounded, no growth).
	if c.Stats().BufferedFlows != 0 {
		t.Error("dropped snapshot must not be re-buffered")
	}

	// Channel up: snapshot forwarded, shadow flag propagates.
	c.Feed(flowSampleDatagram(1, 100, pkt))
	var got Frame
	up := NewForwarder(c, func(v any) error { got = v.(Frame); return nil }, 0, true, nil)
	up.tick()
	if up.Forwarded() != 1 || up.ForwardDrops() != 0 {
		t.Fatalf("up channel: forwarded=%d drops=%d, want 1/0", up.Forwarded(), up.ForwardDrops())
	}
	if got.Type != "data" || got.Kind != "sflow" || !got.Shadow {
		t.Errorf("frame = %+v", got)
	}
	if got.Data.Source != "sflow" {
		t.Errorf("forwarded snapshot shape = %+v", got.Data)
	}
}

func TestCollectorStartStop(t *testing.T) {
	// Port 0 binds an ephemeral UDP port; verify Start binds and cancel stops it.
	c := New(Options{BindAddress: "127.0.0.1", Port: 0})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !c.Stats().Listening {
		t.Error("should be listening after Start")
	}
	cancel()
}
