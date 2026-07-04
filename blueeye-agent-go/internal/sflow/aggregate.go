package sflow

import (
	"sort"
	"strconv"
)

// Entry is one aggregated bucket, matching the Node aggregate output.
type Entry struct {
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Pair     string `json:"pair,omitempty"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
	Flows    int64  `json:"flows"`
}

// Totals is the summary block.
type Totals struct {
	Bytes   int64 `json:"bytes"`
	Packets int64 `json:"packets"`
	Flows   int64 `json:"flows"`
}

// Snapshot is the drained, aggregated flow summary — the exact shape the Node
// sFlow collector's drain() produces (source/datagrams/droppedDatagrams/sampled
// + totals/byPort/byProtocol/topTalkers).
type Snapshot struct {
	Source           string  `json:"source"`
	Datagrams        int64   `json:"datagrams"`
	DroppedDatagrams int64   `json:"droppedDatagrams"`
	Sampled          bool    `json:"sampled"`
	Totals           Totals  `json:"totals"`
	ByPort           []Entry `json:"byPort"`
	ByProtocol       []Entry `json:"byProtocol"`
	TopTalkers       []Entry `json:"topTalkers"`
}

const defaultTopN = 50

// servicePort is the lower of the two non-zero ports (matches aggregate.js).
func servicePort(f Flow) int {
	a, b := f.SrcPort, f.DstPort
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

type acc struct {
	bytes, packets, flows int64
}

// aggregate folds flows into per-port/proto/talker summaries + totals, sorted
// desc by bytes and sliced to topN, exactly as src/netflow/aggregate.js does.
func aggregate(flows []Flow, topN int) (Totals, []Entry, []Entry, []Entry) {
	if topN <= 0 {
		topN = defaultTopN
	}
	byPort := map[int]*acc{}
	byProto := map[string]*acc{}
	byTalker := map[string]*acc{}
	var totals Totals

	add := func(m map[string]*acc, key string, b, p int64) {
		e := m[key]
		if e == nil {
			e = &acc{}
			m[key] = e
		}
		e.bytes += b
		e.packets += p
		e.flows++
	}
	addInt := func(m map[int]*acc, key int, b, p int64) {
		e := m[key]
		if e == nil {
			e = &acc{}
			m[key] = e
		}
		e.bytes += b
		e.packets += p
		e.flows++
	}

	for _, f := range flows {
		totals.Bytes += f.Bytes
		totals.Packets += f.Packets
		totals.Flows++
		addInt(byPort, servicePort(f), f.Bytes, f.Packets)
		protoKey := f.ProtocolName
		if protoKey == "" {
			protoKey = strconv.Itoa(f.Protocol)
		}
		add(byProto, protoKey, f.Bytes, f.Packets)
		add(byTalker, f.SrcAddr+"->"+f.DstAddr, f.Bytes, f.Packets)
	}

	portEntries := make([]Entry, 0, len(byPort))
	for k, v := range byPort {
		portEntries = append(portEntries, Entry{Port: k, Bytes: v.bytes, Packets: v.packets, Flows: v.flows})
	}
	protoEntries := make([]Entry, 0, len(byProto))
	for k, v := range byProto {
		protoEntries = append(protoEntries, Entry{Protocol: k, Bytes: v.bytes, Packets: v.packets, Flows: v.flows})
	}
	talkerEntries := make([]Entry, 0, len(byTalker))
	for k, v := range byTalker {
		talkerEntries = append(talkerEntries, Entry{Pair: k, Bytes: v.bytes, Packets: v.packets, Flows: v.flows})
	}

	sortSlice(portEntries)
	sortSlice(protoEntries)
	sortSlice(talkerEntries)

	return totals, topSlice(portEntries, topN), topSlice(protoEntries, topN), topSlice(talkerEntries, topN)
}

// sortSlice orders desc by bytes; ties broken deterministically by key so output
// is stable (Node relies on insertion order for ties, but a stable secondary key
// keeps the Go output reproducible without affecting the top-N-by-bytes result).
func sortSlice(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].Bytes != es[j].Bytes {
			return es[i].Bytes > es[j].Bytes
		}
		return keyOf(es[i]) < keyOf(es[j])
	})
}

func keyOf(e Entry) string {
	if e.Pair != "" {
		return e.Pair
	}
	if e.Protocol != "" {
		return e.Protocol
	}
	return strconv.Itoa(e.Port)
}

func topSlice(es []Entry, n int) []Entry {
	if len(es) > n {
		return es[:n]
	}
	return es
}
