package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadDef(t *testing.T, rel string) Definition {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var d Definition
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("unmarshal %s: %v", rel, err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("%s invalid: %v", rel, err)
	}
	return d
}

// TestWindowsNetStatsFieldForField checks the windows definition parses the
// pipe-delimited PowerShell output, including an interface name with a space.
func TestWindowsNetStatsFieldForField(t *testing.T) {
	d := loadDef(t, "collectors/windows/net_stats.json")
	// name|rx_bytes|tx_bytes|rx_pkts|tx_pkts|rx_err|tx_err|rx_drop|tx_drop
	canned := "Ethernet|1000|2000|10|20|1|2|3|4\n" +
		"Wi-Fi 2|500|600|5|6|0|0|0|0\n"
	e := newTestEngine(fakeRunner{out: []byte(canned)}, nil)
	res, err := e.CollectOnce(context.Background(), d)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	// Interface name with a space is preserved (delimiter is '|', not whitespace).
	if s, ok := sampleByMetricLabel(res, "net_rx_bytes", "iface", "Wi-Fi 2"); !ok || s.Value != 500 {
		t.Fatalf("Wi-Fi 2 net_rx_bytes = %+v ok=%v", s, ok)
	}
	want := map[string]float64{
		"net_rx_bytes": 1000, "net_tx_bytes": 2000,
		"net_rx_packets": 10, "net_tx_packets": 20,
		"net_rx_errors": 1, "net_tx_errors": 2,
		"net_rx_drop": 3, "net_tx_drop": 4,
	}
	for m, v := range want {
		s, ok := sampleByMetricLabel(res, m, "iface", "Ethernet")
		if !ok || s.Value != v || s.Type != Counter {
			t.Errorf("Ethernet %s = %+v (ok=%v), want %v counter", m, s, ok, v)
		}
	}
}

// TestDarwinNetIbFieldForFieldAndQuirks exercises the two netstat -ib quirks:
// the Address column is present for en0 (MAC) but blank for lo0 (variable width,
// handled by negative indices), and each interface has duplicate rows (handled
// by dedupe_by keeping the Link row).
func TestDarwinNetIbFieldForFieldAndQuirks(t *testing.T) {
	d := loadDef(t, "collectors/darwin/net_ib.json")
	canned := "" +
		"Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\n" +
		"lo0        16384 <Link#1>                            100     0     20000      100     0     20000     0\n" +
		"lo0        16384 127           127.0.0.1             100     -     20000      100     -     20000     -\n" +
		"en0        1500  <Link#4>    a4:83:e7:11:22:33       500     0    900000      400     0    600000     0\n" +
		"en0        1500  192.168.1     192.168.1.10          500     -    900000      400     -    600000     -\n"

	e := newTestEngine(fakeRunner{out: []byte(canned)}, nil)
	res, err := e.CollectOnce(context.Background(), d)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	// 2 interfaces x 6 metrics, no double-counting from address rows.
	if len(res.Samples) != 12 {
		t.Fatalf("want 12 samples (2 ifaces x 6), got %d: %+v", len(res.Samples), res.Samples)
	}
	checks := []struct {
		iface, metric string
		val           float64
	}{
		{"lo0", "net_rx_bytes", 20000}, {"lo0", "net_tx_bytes", 20000},
		{"lo0", "net_rx_packets", 100}, {"lo0", "net_tx_packets", 100},
		{"lo0", "net_rx_errors", 0}, {"lo0", "net_tx_errors", 0},
		{"en0", "net_rx_bytes", 900000}, {"en0", "net_tx_bytes", 600000},
		{"en0", "net_rx_packets", 500}, {"en0", "net_tx_packets", 400},
		{"en0", "net_rx_errors", 0}, {"en0", "net_tx_errors", 0},
	}
	for _, c := range checks {
		s, ok := sampleByMetricLabel(res, c.metric, "iface", c.iface)
		if !ok || s.Value != c.val {
			t.Errorf("%s %s = %+v (ok=%v), want %v", c.iface, c.metric, s, ok, c.val)
		}
	}
}

func TestColumnsNegativeIndexAndDedupe(t *testing.T) {
	p := Parser{
		Type:     ParserColumns,
		DedupeBy: "k",
		Columns: []Column{
			{Index: 0, Field: "k"},
			{Index: -1, Field: "last"},
		},
	}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}
	rows, _ := p.Parse([]byte("a 1 2 9\na 5 6 8\nb 7\n"))
	if len(rows) != 2 {
		t.Fatalf("dedupe: want 2 rows, got %d: %v", len(rows), rows)
	}
	if rows[0]["k"] != "a" || rows[0]["last"] != "9" {
		t.Errorf("row0 = %v (negative index/dedupe wrong)", rows[0])
	}
	if rows[1]["k"] != "b" || rows[1]["last"] != "7" {
		t.Errorf("row1 = %v", rows[1])
	}
}
