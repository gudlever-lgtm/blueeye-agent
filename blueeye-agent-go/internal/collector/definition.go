// Package collector implements the definition-driven collector engine
// (collectors are DATA, not code): the server pushes JSON collector definitions
// over the authenticated WebSocket channel; the engine schedules each one,
// runs its exec sandboxed, parses stdout with a built-in parser, and emits
// metrics. See GO-REWRITE-AUDIT.md and the milestone brief.
package collector

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// ParserType is one of the built-in parser kinds.
type ParserType string

const (
	// ParserRegexLines applies a regexp with named groups to each line; one
	// metric set per matching line.
	ParserRegexLines ParserType = "regex_lines"
	// ParserColumns splits each line on whitespace (or Delimiter) and maps
	// column index -> field name.
	ParserColumns ParserType = "columns"
	// ParserJSON extracts values by dotted path (jq-style) from JSON stdout.
	ParserJSON ParserType = "json"
	// ParserKeyValue reads "key: value" lines.
	ParserKeyValue ParserType = "key_value"
)

// MetricType is a gauge or counter.
type MetricType string

const (
	// Gauge is an instantaneous value.
	Gauge MetricType = "gauge"
	// Counter is a monotonically increasing value.
	Counter MetricType = "counter"
)

// Exec describes how to produce raw output. On linux/darwin, Command+Args are
// run directly with no shell. On windows, PowerShell holds the script body
// (run in the persistent stream — engine infrastructure, later milestone).
type Exec struct {
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	PowerShell string   `json:"powershell,omitempty"`
	// TimeoutSeconds overrides the engine default (10s) for this collector.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Column maps a split index to a field name (columns parser). Trim, if set, is
// a cutset removed from both ends of the field value (e.g. ":" to turn the
// /proc/net/dev interface token "eth0:" into "eth0").
type Column struct {
	Index int    `json:"index"`
	Field string `json:"field"`
	Trim  string `json:"trim,omitempty"`
}

// Parser configures how stdout is turned into metrics.
type Parser struct {
	Type ParserType `json:"type"`
	// regex_lines
	Pattern string `json:"pattern,omitempty"`
	// columns
	Delimiter string   `json:"delimiter,omitempty"` // default: any whitespace
	Columns   []Column `json:"columns,omitempty"`
	// DedupeBy keeps only the FIRST row for each distinct value of the named
	// field (columns parser). This handles `netstat -ib`'s quirk of emitting one
	// row per address family per interface: the first (Link#) row carries the
	// cumulative counters, so keeping it and dropping the rest avoids
	// double-counting.
	DedupeBy string `json:"dedupe_by,omitempty"`
	// A line is skipped when it matches SkipLine (columns/key_value/regex).
	SkipLine string `json:"skip_line,omitempty"`
	// Trim removes a trailing token from a key/field value (e.g. ":" on iface).
	// json
	Paths map[string]string `json:"paths,omitempty"` // field -> dotted path
	// key_value
	Separator string `json:"separator,omitempty"` // default ":"

	compiledPattern *regexp.Regexp
	compiledSkip    *regexp.Regexp
}

// Metric declares an output metric produced by the parser.
type Metric struct {
	Name   string     `json:"name"`
	Type   MetricType `json:"type"`
	Field  string     `json:"field"` // which parsed field supplies the value
	Labels []string   `json:"labels,omitempty"`
}

// Output declares the metrics a definition emits.
type Output struct {
	Metrics []Metric `json:"metrics"`
	// LabelFields are parsed fields attached as labels to every metric of a line
	// (e.g. "iface"). Individual Metric.Labels may add more.
	LabelFields []string `json:"label_fields,omitempty"`
}

// Definition is a full collector definition (the DATA the server pushes).
type Definition struct {
	ID              string `json:"id"`
	Version         int    `json:"version"`
	Platform        string `json:"platform"` // linux/windows/darwin
	IntervalSeconds int    `json:"interval_seconds"`
	Exec            Exec   `json:"exec"`
	Parser          Parser `json:"parser"`
	Output          Output `json:"output"`
}

// ValidPlatforms are the accepted platform values.
var ValidPlatforms = map[string]bool{"linux": true, "windows": true, "darwin": true}

// Validate checks a definition is well-formed and compiles its regexps.
// A malformed definition is rejected (never installed).
func (d *Definition) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("definition: missing id")
	}
	if d.Version < 1 {
		return fmt.Errorf("definition %q: version must be >= 1", d.ID)
	}
	if !ValidPlatforms[d.Platform] {
		return fmt.Errorf("definition %q: invalid platform %q", d.ID, d.Platform)
	}
	if d.IntervalSeconds < 1 {
		return fmt.Errorf("definition %q: interval_seconds must be >= 1", d.ID)
	}
	// exec must specify exactly one mode appropriate to the platform.
	switch d.Platform {
	case "windows":
		if strings.TrimSpace(d.Exec.PowerShell) == "" {
			return fmt.Errorf("definition %q: windows exec needs a powershell body", d.ID)
		}
	default:
		if strings.TrimSpace(d.Exec.Command) == "" {
			return fmt.Errorf("definition %q: exec needs a command", d.ID)
		}
	}
	if err := d.Parser.compile(); err != nil {
		return fmt.Errorf("definition %q: %w", d.ID, err)
	}
	if len(d.Output.Metrics) == 0 {
		return fmt.Errorf("definition %q: output has no metrics", d.ID)
	}
	for i, m := range d.Output.Metrics {
		if strings.TrimSpace(m.Name) == "" {
			return fmt.Errorf("definition %q: metric %d missing name", d.ID, i)
		}
		if m.Type != Gauge && m.Type != Counter {
			return fmt.Errorf("definition %q: metric %q invalid type %q", d.ID, m.Name, m.Type)
		}
		if strings.TrimSpace(m.Field) == "" {
			return fmt.Errorf("definition %q: metric %q missing field", d.ID, m.Name)
		}
	}
	return nil
}

// AppliesHere reports whether this definition targets the running OS.
func (d *Definition) AppliesHere() bool {
	return d.Platform == runtime.GOOS
}

func (p *Parser) compile() error {
	switch p.Type {
	case ParserRegexLines:
		if strings.TrimSpace(p.Pattern) == "" {
			return errors.New("regex_lines parser needs a pattern")
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("bad regex pattern: %w", err)
		}
		if len(re.SubexpNames()) <= 1 {
			return errors.New("regex_lines pattern must have named groups")
		}
		p.compiledPattern = re
	case ParserColumns:
		if len(p.Columns) == 0 {
			return errors.New("columns parser needs at least one column mapping")
		}
	case ParserKeyValue:
		// separator defaults to ":"
	case ParserJSON:
		if len(p.Paths) == 0 {
			return errors.New("json parser needs at least one path")
		}
	default:
		return fmt.Errorf("unknown parser type %q", p.Type)
	}
	if p.SkipLine != "" {
		re, err := regexp.Compile(p.SkipLine)
		if err != nil {
			return fmt.Errorf("bad skip_line regex: %w", err)
		}
		p.compiledSkip = re
	}
	return nil
}
