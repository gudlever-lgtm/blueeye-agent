// Package sflow receives hsflowd sFlow v5 datagrams on a local UDP port, decodes
// them (flow samples + counter samples) into the SAME shape as the Node agent's
// src/sflow decoder, and forwards an aggregated flow summary over the existing
// WebSocket channel. Malformed datagrams are counted and dropped, never fatal.
package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// protoNames mirrors blueeye-agent/src/netflow/fields.js PROTO_NAMES exactly.
var protoNames = map[int]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6"}

func protocolName(p int) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return strconv.Itoa(p)
}

// Flow is one decoded flow record, matching the Node decoder's output fields.
// Bytes/Packets are rate-scaled (each sample stands in for ~samplingRate packets).
type Flow struct {
	SrcAddr      string `json:"srcAddr"`
	DstAddr      string `json:"dstAddr"`
	SrcPort      int    `json:"srcPort"`
	DstPort      int    `json:"dstPort"`
	Protocol     int    `json:"protocol"`
	Bytes        int64  `json:"bytes"`
	Packets      int64  `json:"packets"`
	ProtocolName string `json:"protocolName"`
	Sampled      bool   `json:"sampled"`
}

const (
	ethHdr        = 14
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100
)

// Decode parses an sFlow v5 datagram into flow records and a count of counter
// samples (which carry no per-flow data). It mirrors src/sflow/parse.js and
// returns an error on a malformed/too-short datagram, so the caller counts+drops.
func Decode(buf []byte) (flows []Flow, counterSamples int, err error) {
	if len(buf) < 28 {
		return nil, 0, errors.New("sFlow: datagram too short")
	}
	version := binary.BigEndian.Uint32(buf[0:])
	if version != 5 {
		return nil, 0, fmt.Errorf("sFlow: unsupported version %d", version)
	}
	ipVersion := binary.BigEndian.Uint32(buf[4:])
	o := 8
	if ipVersion == 2 {
		o += 16 // IPv6 agent address
	} else {
		o += 4 // IPv4 agent address
	}
	o += 4 // sub-agent id
	o += 4 // sequence
	o += 4 // uptime
	if o+4 > len(buf) {
		return nil, 0, errors.New("sFlow: truncated header")
	}
	numSamples := int(binary.BigEndian.Uint32(buf[o:]))
	o += 4

	for s := 0; s < numSamples && o+8 <= len(buf); s++ {
		sampleType := binary.BigEndian.Uint32(buf[o:])
		sampleLen := int(binary.BigEndian.Uint32(buf[o+4:]))
		start := o + 8
		end := start + sampleLen
		if end > len(buf) {
			break
		}
		switch sampleType {
		case 1, 3: // (expanded) flow sample
			parseFlowSample(buf, start, end, sampleType == 3, &flows)
		case 2, 4: // (expanded) counter sample — no per-flow data
			counterSamples++
		}
		o = end
	}
	return flows, counterSamples, nil
}

func parseFlowSample(buf []byte, start, end int, expanded bool, flows *[]Flow) {
	p := start
	p += 4 // sequence number
	if expanded {
		p += 8 // source id (expanded)
	} else {
		p += 4 // source id
	}
	if p+16 > end {
		return
	}
	samplingRate := int64(binary.BigEndian.Uint32(buf[p:]))
	p += 4
	p += 4 // sample pool
	p += 4 // drops
	if expanded {
		p += 16 // input+output interface (expanded)
	} else {
		p += 8 // input+output interface
	}
	if p+4 > end {
		return
	}
	numRecords := int(binary.BigEndian.Uint32(buf[p:]))
	p += 4

	rate := samplingRate
	if rate <= 0 {
		rate = 1
	}

	for r := 0; r < numRecords && p+8 <= end; r++ {
		recType := binary.BigEndian.Uint32(buf[p:])
		recLen := int(binary.BigEndian.Uint32(buf[p+4:]))
		recStart := p + 8
		recEnd := recStart + recLen
		if recEnd > end {
			break
		}
		// flow record type 1 = raw packet header (enterprise 0).
		if recType == 1 && recStart+16 <= recEnd {
			frameLength := int(binary.BigEndian.Uint32(buf[recStart+4:]))
			headerLength := int(binary.BigEndian.Uint32(buf[recStart+12:]))
			hStart := recStart + 16
			hEnd := hStart + headerLength
			if hEnd > recEnd {
				hEnd = recEnd
			}
			if hEnd > hStart {
				if flow, ok := decodeSampledHeader(buf[hStart:hEnd], frameLength); ok {
					flow.Bytes *= rate
					flow.Packets *= rate
					flow.Sampled = true
					*flows = append(*flows, flow)
				}
			}
		}
		p = recEnd
	}
}

// decodeSampledHeader decodes Ethernet II (+ up to one VLAN tag) + IPv4/IPv6 +
// TCP/UDP far enough for the 5-tuple, matching src/sflow/decodePacket.js.
func decodeSampledHeader(header []byte, frameLength int) (Flow, bool) {
	if len(header) < ethHdr+20 {
		return Flow{}, false
	}
	etherType := int(binary.BigEndian.Uint16(header[12:]))
	l3 := ethHdr
	if etherType == etherTypeVLAN && len(header) >= l3+4 {
		etherType = int(binary.BigEndian.Uint16(header[l3+2:]))
		l3 += 4
	}

	bytes := int64(len(header))
	if frameLength > 0 {
		bytes = int64(frameLength)
	}
	flow := Flow{SrcAddr: "0.0.0.0", DstAddr: "0.0.0.0", Bytes: bytes, Packets: 1}

	switch etherType {
	case etherTypeIPv4:
		if len(header) < l3+20 {
			return Flow{}, false
		}
		ihl := int(header[l3]&0x0f) * 4
		flow.Protocol = int(header[l3+9])
		flow.SrcAddr = ipv4(header, l3+12)
		flow.DstAddr = ipv4(header, l3+16)
		l4 := l3 + ihl
		if ihl < 20 {
			l4 = l3 + 20
		}
		flow.SrcPort, flow.DstPort = readPorts(header, l4, flow.Protocol)
	case etherTypeIPv6:
		if len(header) < l3+40 {
			return Flow{}, false
		}
		flow.Protocol = int(header[l3+6]) // next header (no extension walking)
		flow.SrcAddr = ipv6(header, l3+8)
		flow.DstAddr = ipv6(header, l3+24)
		flow.SrcPort, flow.DstPort = readPorts(header, l3+40, flow.Protocol)
	default:
		return Flow{}, false // not IP
	}
	flow.ProtocolName = protocolName(flow.Protocol)
	return flow, true
}

func readPorts(buf []byte, o, protocol int) (int, int) {
	if (protocol == 6 || protocol == 17) && o+4 <= len(buf) {
		return int(binary.BigEndian.Uint16(buf[o:])), int(binary.BigEndian.Uint16(buf[o+2:]))
	}
	return 0, 0
}

// ipv4 / ipv6 match src/netflow/ip.js exactly (ipv6 emits 8 uncompressed hex
// groups joined by ':', no zero-compression).
func ipv4(buf []byte, off int) string {
	return fmt.Sprintf("%d.%d.%d.%d", buf[off], buf[off+1], buf[off+2], buf[off+3])
}

func ipv6(buf []byte, off int) string {
	parts := make([]string, 0, 8)
	for i := 0; i < 16; i += 2 {
		parts = append(parts, strconv.FormatUint(uint64(binary.BigEndian.Uint16(buf[off+i:])), 16))
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ":" + p
	}
	return out
}
