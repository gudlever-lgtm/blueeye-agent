package sflow

import (
	"encoding/binary"
	"testing"
)

// --- datagram builders (shared across the package's tests) ---

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// rawPacketIPv4TCP builds an Ethernet+IPv4+TCP header for the sampled packet.
func rawPacketIPv4TCP(src, dst [4]byte, sport, dport uint16, proto byte) []byte {
	h := make([]byte, 38)
	// Ethernet: 12 bytes MAC (zero) + ethertype IPv4.
	binary.BigEndian.PutUint16(h[12:], etherTypeIPv4)
	// IPv4 header (20 bytes) starting at offset 14.
	h[14] = 0x45 // version 4, IHL 5 (20 bytes)
	h[14+9] = proto
	copy(h[14+12:], src[:])
	copy(h[14+16:], dst[:])
	// TCP/UDP ports at offset 14+20 = 34.
	binary.BigEndian.PutUint16(h[34:], sport)
	binary.BigEndian.PutUint16(h[36:], dport)
	return h
}

// flowSampleDatagram wraps one raw-packet-header flow record in a v5 datagram.
func flowSampleDatagram(samplingRate, frameLength uint32, pkt []byte) []byte {
	// record: recType(1) recLen | header_protocol(1) frame_length stripped header_length header[]
	rec := []byte{}
	rec = append(rec, be32(1)...)                    // header_protocol = ethernet
	rec = append(rec, be32(frameLength)...)          // frame_length
	rec = append(rec, be32(0)...)                    // stripped
	rec = append(rec, be32(uint32(len(pkt)))...)     // header_length
	rec = append(rec, pkt...)                         // header bytes
	recBlock := append(be32(1), be32(uint32(len(rec)))...)
	recBlock = append(recBlock, rec...)

	body := []byte{}
	body = append(body, be32(1)...)            // sample sequence
	body = append(body, be32(0)...)            // source id
	body = append(body, be32(samplingRate)...) // sampling rate
	body = append(body, be32(0)...)            // sample pool
	body = append(body, be32(0)...)            // drops
	body = append(body, be32(0)...)            // input iface
	body = append(body, be32(0)...)            // output iface
	body = append(body, be32(1)...)            // num records
	body = append(body, recBlock...)

	sample := append(be32(1), be32(uint32(len(body)))...) // sampleType 1, length
	sample = append(sample, body...)

	dg := []byte{}
	dg = append(dg, be32(5)...) // version
	dg = append(dg, be32(1)...) // ipVersion = IPv4
	dg = append(dg, be32(0)...) // agent addr
	dg = append(dg, be32(0)...) // sub-agent id
	dg = append(dg, be32(0)...) // sequence
	dg = append(dg, be32(0)...) // uptime
	dg = append(dg, be32(1)...) // num samples
	dg = append(dg, sample...)
	return dg
}

func counterSampleDatagram() []byte {
	body := make([]byte, 16) // arbitrary counter body
	sample := append(be32(2), be32(uint32(len(body)))...)
	sample = append(sample, body...)
	dg := []byte{}
	dg = append(dg, be32(5)...)
	dg = append(dg, be32(1)...)
	dg = append(dg, be32(0)...)
	dg = append(dg, be32(0)...)
	dg = append(dg, be32(0)...)
	dg = append(dg, be32(0)...)
	dg = append(dg, be32(1)...) // one sample
	dg = append(dg, sample...)
	return dg
}

func TestDecodeFlowSampleIPv4TCP(t *testing.T) {
	pkt := rawPacketIPv4TCP([4]byte{10, 0, 0, 1}, [4]byte{93, 184, 216, 34}, 12345, 443, 6)
	dg := flowSampleDatagram(1000, 1500, pkt)

	flows, counters, err := Decode(dg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if counters != 0 {
		t.Errorf("counterSamples = %d, want 0", counters)
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	f := flows[0]
	if f.SrcAddr != "10.0.0.1" || f.DstAddr != "93.184.216.34" {
		t.Errorf("addrs = %s -> %s", f.SrcAddr, f.DstAddr)
	}
	if f.SrcPort != 12345 || f.DstPort != 443 || f.Protocol != 6 || f.ProtocolName != "tcp" {
		t.Errorf("l4 = %d->%d proto %d/%s", f.SrcPort, f.DstPort, f.Protocol, f.ProtocolName)
	}
	// bytes = frameLength * samplingRate; packets = 1 * samplingRate.
	if f.Bytes != 1500*1000 || f.Packets != 1000 {
		t.Errorf("scaled bytes=%d packets=%d, want 1500000/1000", f.Bytes, f.Packets)
	}
	if !f.Sampled {
		t.Error("sampled should be true")
	}
}

func TestDecodeCounterSample(t *testing.T) {
	flows, counters, err := Decode(counterSampleDatagram())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(flows) != 0 || counters != 1 {
		t.Fatalf("want 0 flows / 1 counter, got %d / %d", len(flows), counters)
	}
}

func TestDecodeMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":    make([]byte, 10),
		"bad version":  append(be32(4), make([]byte, 30)...),
		"truncated hdr": be32(5), // version only
	}
	for name, dg := range cases {
		if _, _, err := Decode(dg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodeIPv6UDP(t *testing.T) {
	// Ethernet + IPv6(40) + UDP ports. next-header (proto) at l3+6, addrs at +8/+24.
	h := make([]byte, ethHdr+40+4)
	binary.BigEndian.PutUint16(h[12:], etherTypeIPv6)
	h[ethHdr+6] = 17 // next header = UDP
	h[ethHdr+8] = 0x20
	h[ethHdr+9] = 0x01 // src starts 2001:...
	h[ethHdr+24] = 0xfe
	h[ethHdr+25] = 0x80 // dst starts fe80:...
	binary.BigEndian.PutUint16(h[ethHdr+40:], 53)
	binary.BigEndian.PutUint16(h[ethHdr+42:], 5353)
	dg := flowSampleDatagram(1, 100, h)
	flows, _, err := Decode(dg)
	if err != nil || len(flows) != 1 {
		t.Fatalf("decode ipv6: err=%v flows=%d", err, len(flows))
	}
	f := flows[0]
	if f.Protocol != 17 || f.ProtocolName != "udp" || f.SrcPort != 53 || f.DstPort != 5353 {
		t.Errorf("ipv6/udp = proto %d/%s ports %d->%d", f.Protocol, f.ProtocolName, f.SrcPort, f.DstPort)
	}
	// Node emits 8 uncompressed hex groups joined by ':'.
	if f.SrcAddr != "2001:0:0:0:0:0:0:0" {
		t.Errorf("ipv6 src = %q (want uncompressed groups)", f.SrcAddr)
	}
}
