package collector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Row is one parsed record: field name -> string value. regex_lines and columns
// produce one Row per matching line; key_value and json produce a single Row.
type Row map[string]string

// Parse turns raw stdout into rows using the configured parser. A parse error
// (e.g. malformed JSON) is returned so the engine can log-and-skip; it never
// panics. Lines matching SkipLine are dropped.
func (p *Parser) Parse(stdout []byte) ([]Row, error) {
	if p.compiledPattern == nil && p.compiledSkip == nil {
		// Ensure regexps are compiled even if Validate wasn't called (defensive).
		if err := p.compile(); err != nil {
			return nil, err
		}
	}
	switch p.Type {
	case ParserRegexLines:
		return p.parseRegexLines(stdout), nil
	case ParserColumns:
		return p.parseColumns(stdout), nil
	case ParserKeyValue:
		return p.parseKeyValue(stdout), nil
	case ParserJSON:
		return p.parseJSON(stdout)
	default:
		return nil, fmt.Errorf("unknown parser type %q", p.Type)
	}
}

func (p *Parser) skip(line string) bool {
	return p.compiledSkip != nil && p.compiledSkip.MatchString(line)
}

func lines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

func (p *Parser) parseRegexLines(b []byte) []Row {
	var rows []Row
	names := p.compiledPattern.SubexpNames()
	for _, line := range lines(b) {
		if strings.TrimSpace(line) == "" || p.skip(line) {
			continue
		}
		m := p.compiledPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		row := Row{}
		for i, name := range names {
			if i == 0 || name == "" {
				continue
			}
			row[name] = m[i]
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}
	return rows
}

func (p *Parser) parseColumns(b []byte) []Row {
	var rows []Row
	for _, line := range lines(b) {
		if strings.TrimSpace(line) == "" || p.skip(line) {
			continue
		}
		var fields []string
		if p.Delimiter != "" {
			fields = splitTrim(line, p.Delimiter)
		} else {
			fields = strings.Fields(line)
		}
		row := Row{}
		ok := false
		for _, col := range p.Columns {
			if col.Index < 0 || col.Index >= len(fields) {
				continue
			}
			v := fields[col.Index]
			if col.Trim != "" {
				v = strings.Trim(v, col.Trim)
			}
			row[col.Field] = v
			ok = true
		}
		if ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func splitTrim(line, delim string) []string {
	parts := strings.Split(line, delim)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func (p *Parser) parseKeyValue(b []byte) []Row {
	sep := p.Separator
	if sep == "" {
		sep = ":"
	}
	row := Row{}
	for _, line := range lines(b) {
		if strings.TrimSpace(line) == "" || p.skip(line) {
			continue
		}
		idx := strings.Index(line, sep)
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+len(sep):])
		if key == "" {
			continue
		}
		row[key] = val
	}
	if len(row) == 0 {
		return nil
	}
	return []Row{row}
}

func (p *Parser) parseJSON(b []byte) ([]Row, error) {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("json parser: %w", err)
	}
	row := Row{}
	for field, path := range p.Paths {
		v, ok := lookupPath(doc, path)
		if !ok {
			continue
		}
		row[field] = stringify(v)
	}
	if len(row) == 0 {
		return nil, nil
	}
	return []Row{row}, nil
}

// lookupPath walks a dotted path (jq-style, e.g. "a.b.0.c") over decoded JSON.
func lookupPath(doc any, path string) (any, bool) {
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// Render integers without a trailing ".000000".
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
