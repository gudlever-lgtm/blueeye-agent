package sflow

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// DefaultMaxFlows bounds the in-memory flow buffer (matches the Node collector).
const DefaultMaxFlows = 100000

// Collector listens for sFlow v5 datagrams on a local UDP port, decodes them and
// buffers the flow records until Drain. Malformed datagrams are counted and
// dropped; the buffer is bounded so a flood can't grow memory without limit.
type Collector struct {
	addr      string
	maxFlows  int
	logger    *logx.Logger
	now       func() time.Time

	mu             sync.Mutex
	buffer         []Flow
	received       int64 // datagrams decoded OK
	dropped        int64 // malformed datagrams
	decoded        int64 // cumulative flow records decoded (survives drain)
	counterSamples int64
	bufferOverflow int64 // flow records dropped because the buffer was full
	lastAt         *time.Time
	bound          bool

	conn *net.UDPConn
}

// Options configures a Collector. BindAddress defaults to 127.0.0.1 (the local
// hsflowd exporter), Port to 6343.
type Options struct {
	BindAddress string
	Port        int
	MaxFlows    int
	Logger      *logx.Logger
	Now         func() time.Time
}

// New builds a Collector (does not bind until Start).
func New(o Options) *Collector {
	if o.BindAddress == "" {
		o.BindAddress = "127.0.0.1"
	}
	if o.Port == 0 {
		o.Port = 6343
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = DefaultMaxFlows
	}
	if o.Logger == nil {
		o.Logger = logx.New(logx.Info)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Collector{
		addr:     net.JoinHostPort(o.BindAddress, itoa(o.Port)),
		maxFlows: o.MaxFlows,
		logger:   o.Logger,
		now:      o.Now,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Feed decodes one datagram as if received over UDP (also used by tests). A
// malformed datagram increments dropped and is ignored — never a crash.
func (c *Collector) Feed(msg []byte) {
	t := c.now()
	flows, counters, err := Decode(msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastAt = &t
	if err != nil {
		c.dropped++
		c.logger.Debugf("sFlow: dropped a datagram (%v)", err)
		return
	}
	c.decoded += int64(len(flows))
	c.counterSamples += int64(counters)
	for _, f := range flows {
		if len(c.buffer) >= c.maxFlows {
			c.bufferOverflow++
			continue
		}
		c.buffer = append(c.buffer, f)
	}
	c.received++
}

// Start binds the UDP socket and reads datagrams until ctx is cancelled.
func (c *Collector) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", c.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.conn = conn
	c.bound = true
	c.mu.Unlock()
	c.logger.Infof("sFlow collector listening on %s", c.addr)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				c.mu.Lock()
				c.bound = false
				c.mu.Unlock()
				return
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			c.Feed(msg)
		}
	}()
	return nil
}

// Drain returns the aggregated snapshot of buffered flows and clears the buffer.
func (c *Collector) Drain() Snapshot {
	c.mu.Lock()
	flows := c.buffer
	c.buffer = nil
	received := c.received
	dropped := c.dropped
	c.mu.Unlock()

	totals, byPort, byProto, talkers := aggregate(flows, defaultTopN)
	return Snapshot{
		Source:           "sflow",
		Datagrams:        received,
		DroppedDatagrams: dropped,
		Sampled:          true,
		Totals:           totals,
		ByPort:           byPort,
		ByProtocol:       byProto,
		TopTalkers:       talkers,
	}
}

// Stats is a non-draining health snapshot (for a future diagnose command).
type Stats struct {
	Listening      bool   `json:"listening"`
	Datagrams      int64  `json:"datagrams"`
	Dropped        int64  `json:"dropped"`
	DecodedFlows   int64  `json:"decodedFlows"`
	CounterSamples int64  `json:"counterSamples"`
	BufferedFlows  int    `json:"bufferedFlows"`
	BufferOverflow int64  `json:"bufferOverflow"`
	LastDatagramAt string `json:"lastDatagramAt"`
}

// Stats returns a non-destructive health snapshot.
func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	last := ""
	if c.lastAt != nil {
		last = c.lastAt.UTC().Format(time.RFC3339)
	}
	return Stats{
		Listening: c.bound, Datagrams: c.received, Dropped: c.dropped,
		DecodedFlows: c.decoded, CounterSamples: c.counterSamples,
		BufferedFlows: len(c.buffer), BufferOverflow: c.bufferOverflow, LastDatagramAt: last,
	}
}
