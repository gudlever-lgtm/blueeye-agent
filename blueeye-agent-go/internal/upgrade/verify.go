// Package upgrade implements the Go agent's self-update: download a new binary
// over REST, verify its Ed25519 signature over the canonical manifest BEFORE
// touching disk (fail-closed on any verification error), record a two-state
// audit, then self-replace the running binary per platform. The collector
// definitions cache lives elsewhere and is never touched by an upgrade.
package upgrade

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

// canonicalize reproduces blueeye-agent/src/release/canonicalize.js: parse the
// JSON, sort object keys recursively, emit compact (no whitespace) UTF-8. Go's
// encoding/json sorts map keys and marshals compactly, so unmarshal→marshal is
// byte-identical for the (string/number/bool) manifests used here.
func canonicalize(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// parsePublicKey decodes a PEM SubjectPublicKeyInfo into an ed25519 public key.
func parsePublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("not a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return edPub, nil
}

// VerifyManifest verifies an Ed25519 signature over the canonical manifest bytes,
// mirroring blueeye-agent/src/release/verifyManifest.js. Any error (bad key, bad
// encoding, tampering) returns false — the caller fails CLOSED and never installs
// code it cannot authenticate.
func VerifyManifest(manifestJSON []byte, signature []byte, publicKeyPEM string) bool {
	if len(manifestJSON) == 0 || len(signature) == 0 || publicKeyPEM == "" {
		return false
	}
	pub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false
	}
	msg, err := canonicalize(manifestJSON)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, signature)
}
