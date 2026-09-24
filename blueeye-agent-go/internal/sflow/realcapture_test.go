package sflow

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Real hsflowd 2.1.26 datagrams, shared with the Node agent's
// test/sflowRealCapture.test.js (see test/fixtures/sflow/README.md). The
// totals below are facts of the capture, and are what the Node parser reads
// from the same bytes — so this is the Go/Node parity check on real input
// rather than on hand-built datagrams.
const realCaptureDir = "../../../test/fixtures/sflow"

func TestDecodeRealHsflowdCapture(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(realCaptureDir, "hsflowd-*.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("expected the captured run, found %d files", len(files))
	}
	sort.Strings(files)

	hosts := map[string]bool{"198.51.100.1": true, "198.51.100.2": true}
	var flows, counters int
	var bytes int64
	for _, f := range files {
		buf, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fl, cs, err := Decode(buf)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		for _, x := range fl {
			if !hosts[x.SrcAddr] || !hosts[x.DstAddr] {
				t.Errorf("%s: unexpected endpoints %s -> %s", filepath.Base(f), x.SrcAddr, x.DstAddr)
			}
			if x.Packets != 8 || !x.Sampled {
				t.Errorf("%s: packets %d sampled %v, want 8 (1-in-8) and true", filepath.Base(f), x.Packets, x.Sampled)
			}
			if x.Bytes <= 0 || x.Bytes%8 != 0 {
				t.Errorf("%s: bytes %d not a frame length scaled by 8", filepath.Base(f), x.Bytes)
			}
			switch x.ProtocolName {
			case "tcp", "udp", "icmp":
			default:
				t.Errorf("%s: protocol %q", filepath.Base(f), x.ProtocolName)
			}
		}
		flows += len(fl)
		counters += cs
		for _, x := range fl {
			bytes += x.Bytes
		}
	}
	// Same numbers src/sflow/parse.js reads from these files.
	if flows != 75 || counters != 16 || bytes != 662984 {
		t.Fatalf("totals flows=%d counters=%d bytes=%d, want 75/16/662984 (the Node parser's)", flows, counters, bytes)
	}
}
