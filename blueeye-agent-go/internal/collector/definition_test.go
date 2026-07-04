package collector

import "testing"

func validLinuxDef() Definition {
	return Definition{
		ID:              "linux.x",
		Version:         1,
		Platform:        "linux",
		IntervalSeconds: 60,
		Exec:            Exec{Command: "cat", Args: []string{"/proc/loadavg"}},
		Parser:          Parser{Type: ParserColumns, Columns: []Column{{Index: 0, Field: "a"}}},
		Output:          Output{Metrics: []Metric{{Name: "a", Type: Gauge, Field: "a"}}},
	}
}

func TestValidateAcceptsValid(t *testing.T) {
	d := validLinuxDef()
	if err := d.Validate(); err != nil {
		t.Fatalf("valid def rejected: %v", err)
	}
}

func TestValidateMalformed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Definition)
	}{
		{"no id", func(d *Definition) { d.ID = "" }},
		{"zero version", func(d *Definition) { d.Version = 0 }},
		{"bad platform", func(d *Definition) { d.Platform = "solaris" }},
		{"zero interval", func(d *Definition) { d.IntervalSeconds = 0 }},
		{"no command", func(d *Definition) { d.Exec.Command = "" }},
		{"no metrics", func(d *Definition) { d.Output.Metrics = nil }},
		{"bad metric type", func(d *Definition) { d.Output.Metrics[0].Type = "histogram" }},
		{"metric no field", func(d *Definition) { d.Output.Metrics[0].Field = "" }},
		{"columns no mapping", func(d *Definition) { d.Parser = Parser{Type: ParserColumns} }},
		{"unknown parser", func(d *Definition) { d.Parser = Parser{Type: "xml"} }},
		{"regex no pattern", func(d *Definition) { d.Parser = Parser{Type: ParserRegexLines} }},
		{"json no paths", func(d *Definition) { d.Parser = Parser{Type: ParserJSON} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validLinuxDef()
			tc.mut(&d)
			if err := d.Validate(); err == nil {
				t.Fatalf("%s: expected validation error", tc.name)
			}
		})
	}
}

func TestValidateWindowsNeedsPowerShell(t *testing.T) {
	d := validLinuxDef()
	d.Platform = "windows"
	d.Exec = Exec{Command: "cmd"} // no powershell body
	if err := d.Validate(); err == nil {
		t.Fatal("windows def without powershell body should be rejected")
	}
	d.Exec = Exec{PowerShell: "Get-NetAdapter"}
	if err := d.Validate(); err != nil {
		t.Fatalf("windows def with powershell body rejected: %v", err)
	}
}
