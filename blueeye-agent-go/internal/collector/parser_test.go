package collector

import (
	"reflect"
	"sort"
	"testing"
)

func TestParsersTableDriven(t *testing.T) {
	cases := []struct {
		name   string
		parser Parser
		input  string
		want   []Row
	}{
		{
			name: "regex_lines named groups",
			parser: Parser{
				Type:    ParserRegexLines,
				Pattern: `^(?P<iface>\w+)\s+(?P<rx>\d+)\s+(?P<tx>\d+)$`,
			},
			input: "eth0 100 200\nlo 5 5\ngarbage line\n",
			want: []Row{
				{"iface": "eth0", "rx": "100", "tx": "200"},
				{"iface": "lo", "rx": "5", "tx": "5"},
			},
		},
		{
			name: "columns whitespace with trim and skip",
			parser: Parser{
				Type:     ParserColumns,
				SkipLine: `\|`,
				Columns: []Column{
					{Index: 0, Field: "iface", Trim: ":"},
					{Index: 1, Field: "rx_bytes"},
					{Index: 9, Field: "tx_bytes"},
				},
			},
			input: " face |bytes    packets\n" +
				"  eth0: 3259151 11051 0 22 0 0 0 0 27429535 11301\n",
			want: []Row{
				{"iface": "eth0", "rx_bytes": "3259151", "tx_bytes": "27429535"},
			},
		},
		{
			name: "columns explicit delimiter",
			parser: Parser{
				Type:      ParserColumns,
				Delimiter: ",",
				Columns:   []Column{{Index: 0, Field: "a"}, {Index: 2, Field: "c"}},
			},
			input: "1, 2, 3\n4,5,6\n",
			want: []Row{
				{"a": "1", "c": "3"},
				{"a": "4", "c": "6"},
			},
		},
		{
			name:   "key_value default colon",
			parser: Parser{Type: ParserKeyValue},
			input:  "MemTotal: 16333512\nMemFree: 900\n\nBroken\n",
			want:   []Row{{"MemTotal": "16333512", "MemFree": "900"}},
		},
		{
			name:   "key_value custom separator",
			parser: Parser{Type: ParserKeyValue, Separator: "="},
			input:  "a=1\nb = 2\n",
			want:   []Row{{"a": "1", "b": "2"}},
		},
		{
			name: "json dotted and array paths",
			parser: Parser{
				Type: ParserJSON,
				Paths: map[string]string{
					"cpu":   "system.cpuPercent",
					"load1": "system.loadavg.0",
					"name":  "host.name",
				},
			},
			input: `{"system":{"cpuPercent":12.5,"loadavg":[0.1,0.2]},"host":{"name":"h1"}}`,
			want:  []Row{{"cpu": "12.5", "load1": "0.1", "name": "h1"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parser.compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := tc.parser.Parse([]byte(tc.input))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(normalizeRows(got), normalizeRows(tc.want)) {
				t.Fatalf("rows mismatch\n got=%v\nwant=%v", got, tc.want)
			}
		})
	}
}

func TestParseJSONMalformed(t *testing.T) {
	p := Parser{Type: ParserJSON, Paths: map[string]string{"x": "a"}}
	_ = p.compile()
	if _, err := p.Parse([]byte("{not json")); err == nil {
		t.Fatal("expected error for malformed json")
	}
}

func TestRegexLinesRequiresNamedGroups(t *testing.T) {
	p := Parser{Type: ParserRegexLines, Pattern: `\d+`}
	if err := p.compile(); err == nil {
		t.Fatal("expected error: pattern without named groups")
	}
}

// normalizeRows makes []Row order-independent for comparison.
func normalizeRows(rows []Row) []Row {
	out := append([]Row(nil), rows...)
	sort.Slice(out, func(i, j int) bool {
		return keysOf(out[i]) < keysOf(out[j])
	})
	if out == nil {
		return []Row{}
	}
	return out
}

func keysOf(r Row) string {
	ks := make([]string, 0, len(r))
	for k, v := range r {
		ks = append(ks, k+"="+v)
	}
	sort.Strings(ks)
	s := ""
	for _, k := range ks {
		s += k + ";"
	}
	return s
}
