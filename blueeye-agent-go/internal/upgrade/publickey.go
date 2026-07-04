package upgrade

import (
	"encoding/base64"
	"strings"
)

// placeholder marks the embedded key as not-yet-provisioned (mirrors the Node
// agent's REPLACE_WITH_… sentinel).
const placeholder = "REPLACE_WITH_BLUEEYE_AGENT_RELEASE_PUBLIC_KEY"

func looksLikePEM(s string) bool { return strings.Contains(s, "BEGIN PUBLIC KEY") }

// ResolveReleasePublicKey mirrors src/release/publicKey.js: BLUEEYE_RELEASE_PUBLIC_KEY
// (PEM or base64-of-PEM) wins; returns "" when only the placeholder is present so
// callers fail closed on a falsy key.
func ResolveReleasePublicKey(env func(string) string) string {
	raw := ""
	if env != nil {
		raw = env("BLUEEYE_RELEASE_PUBLIC_KEY")
	}
	key := ""
	// Keep the key content verbatim (like the Node agent); only the emptiness
	// check ignores surrounding whitespace.
	if strings.TrimSpace(raw) != "" {
		if looksLikePEM(raw) {
			key = raw
		} else if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && looksLikePEM(string(decoded)) {
			key = string(decoded)
		} else {
			key = raw
		}
	}
	if !looksLikePEM(key) || strings.Contains(key, placeholder) {
		return ""
	}
	return key
}
