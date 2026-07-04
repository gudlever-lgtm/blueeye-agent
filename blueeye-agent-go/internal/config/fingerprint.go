package config

import (
	"regexp"
	"strings"
)

var (
	fpPrefix  = regexp.MustCompile(`(?i)^sha-?256[:/=\s]+`)
	nonHexRe  = regexp.MustCompile(`[^0-9a-fA-F]`)
	pairSplit = regexp.MustCompile(`.{2}`)
)

// NormalizeFingerprint mirrors src/fingerprint.js: upper-case hex pairs joined
// by ':' so "ab:cd…", "ABCD…" and "sha256:AB:CD…" all compare equal. Returns ""
// for anything that isn't a 32-byte (64 hex char) SHA-256 digest.
func NormalizeFingerprint(input string) string {
	if input == "" {
		return ""
	}
	s := strings.TrimSpace(input)
	s = fpPrefix.ReplaceAllString(s, "")
	s = nonHexRe.ReplaceAllString(s, "")
	s = strings.ToUpper(s)
	if len(s) != 64 {
		return ""
	}
	return strings.Join(pairSplit.FindAllString(s, -1), ":")
}
