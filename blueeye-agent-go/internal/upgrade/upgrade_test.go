package upgrade

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
)

func keypairPEM(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signedDownload(t *testing.T, priv ed25519.PrivateKey, data []byte, version string) *Download {
	t.Helper()
	mfJSON := []byte(fmt.Sprintf(`{"version":%q,"sha256":%q}`, version, sha256Hex(data)))
	canon, err := canonicalize(mfJSON)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canon)
	return &Download{
		Data:      data,
		Manifest:  base64.StdEncoding.EncodeToString(mfJSON),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

type fixture struct {
	target    string
	cacheFile string
	restarted bool
	records   []audit.Record
	updater   *Updater
}

func newFixture(t *testing.T, priv ed25519.PrivateKey, pubPEM string, dl *Download, dlErr error) *fixture {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "blueeye-agent")
	if err := os.WriteFile(target, []byte("OLD BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A separate collector-definitions cache dir that upgrades must NOT touch.
	cacheDir := filepath.Join(dir, "definitions")
	_ = os.MkdirAll(cacheDir, 0o700)
	cacheFile := filepath.Join(cacheDir, "linux.net_dev.json")
	_ = os.WriteFile(cacheFile, []byte(`{"id":"linux.net_dev"}`), 0o600)

	f := &fixture{target: target, cacheFile: cacheFile}
	al := audit.New("", func(r audit.Record) { f.records = append(f.records, r) })
	f.updater = New(Config{
		Download:  func(context.Context) (*Download, error) { return dl, dlErr },
		Audit:     al,
		PublicKey: pubPEM,
		ExePath:   target,
		GOOS:      "linux",
		Restart:   func() error { f.restarted = true; return nil },
	})
	return f
}

func (f *fixture) targetBytes(t *testing.T) string {
	b, err := os.ReadFile(f.target)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) assertNotSwapped(t *testing.T) {
	t.Helper()
	if f.targetBytes(t) != "OLD BINARY" {
		t.Error("binary was swapped despite a verification failure")
	}
	if f.restarted {
		t.Error("restart called despite a verification failure")
	}
}

func codeOf(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func TestUpdateSuccess(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	data := []byte("NEW BINARY BYTES v1.2.3")
	f := newFixture(t, priv, pubPEM, signedDownload(t, priv, data, "1.2.3"), nil)

	if err := f.updater.Update(context.Background(), Command{Version: "1.2.3"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if f.targetBytes(t) != string(data) {
		t.Error("binary not replaced with new bytes")
	}
	if !f.restarted {
		t.Error("restart not called after a successful update")
	}
	// Two-state audit: initiated then completed.
	if len(f.records) != 2 || f.records[0].State != audit.Initiated || f.records[1].State != audit.Completed {
		t.Fatalf("audit states = %+v", f.records)
	}
	// Collector definitions cache untouched.
	if b, _ := os.ReadFile(f.cacheFile); string(b) != `{"id":"linux.net_dev"}` {
		t.Error("collector cache was modified by the upgrade")
	}
}

func TestUpdateSignatureTamper(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	data := []byte("payload")
	dl := signedDownload(t, priv, data, "1.0.0")
	// Swap the manifest for a different one (old signature no longer matches).
	dl.Manifest = base64.StdEncoding.EncodeToString([]byte(`{"version":"9.9.9","sha256":"` + sha256Hex(data) + `"}`))
	f := newFixture(t, priv, pubPEM, dl, nil)

	err := f.updater.Update(context.Background(), Command{Version: "9.9.9"})
	if codeOf(err) != SignatureInvalid {
		t.Fatalf("code = %v, want SIGNATURE_INVALID", codeOf(err))
	}
	f.assertNotSwapped(t)
	if f.records[1].State != audit.Failed {
		t.Error("audit should record failed")
	}
}

func TestUpdateSignatureBitFlip(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	data := []byte("payload")
	dl := signedDownload(t, priv, data, "1.0.0")
	sig, _ := base64.StdEncoding.DecodeString(dl.Signature)
	sig[0] ^= 0xff
	dl.Signature = base64.StdEncoding.EncodeToString(sig)
	f := newFixture(t, priv, pubPEM, dl, nil)

	if codeOf(f.updater.Update(context.Background(), Command{Version: "1.0.0"})) != SignatureInvalid {
		t.Fatal("bit-flipped signature must fail SIGNATURE_INVALID")
	}
	f.assertNotSwapped(t)
}

func TestUpdateWrongKey(t *testing.T) {
	priv, _ := keypairPEM(t)
	_, otherPub := keypairPEM(t) // sign with priv, verify with a DIFFERENT key
	data := []byte("payload")
	f := newFixture(t, priv, otherPub, signedDownload(t, priv, data, "1.0.0"), nil)
	if codeOf(f.updater.Update(context.Background(), Command{Version: "1.0.0"})) != SignatureInvalid {
		t.Fatal("wrong key must fail SIGNATURE_INVALID")
	}
	f.assertNotSwapped(t)
}

func TestUpdateTruncatedDownload(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	data := []byte("full binary content")
	dl := signedDownload(t, priv, data, "1.0.0")
	dl.Data = data[:len(data)-3] // truncated after signing -> sha mismatch
	f := newFixture(t, priv, pubPEM, dl, nil)
	if codeOf(f.updater.Update(context.Background(), Command{Version: "1.0.0"})) != ChecksumMismatch {
		t.Fatal("truncated download must fail CHECKSUM_MISMATCH")
	}
	f.assertNotSwapped(t)
}

func TestUpdateVersionMismatch(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	data := []byte("payload")
	f := newFixture(t, priv, pubPEM, signedDownload(t, priv, data, "1.0.0"), nil)
	if codeOf(f.updater.Update(context.Background(), Command{Version: "2.0.0"})) != VersionMismatch {
		t.Fatal("version mismatch expected")
	}
	f.assertNotSwapped(t)
}

func TestUpdateNoPublicKeyFailsClosed(t *testing.T) {
	priv, _ := keypairPEM(t)
	data := []byte("payload")
	f := newFixture(t, priv, "", signedDownload(t, priv, data, "1.0.0"), nil) // no key
	if codeOf(f.updater.Update(context.Background(), Command{Version: "1.0.0"})) != NoPublicKey {
		t.Fatal("missing key must fail NO_PUBLIC_KEY (fail-closed)")
	}
	f.assertNotSwapped(t)
}

func TestUpdateDownloadError(t *testing.T) {
	priv, pubPEM := keypairPEM(t)
	f := newFixture(t, priv, pubPEM, nil, fail(DownloadFailed, "download HTTP 404"))
	if codeOf(f.updater.Update(context.Background(), Command{Version: "1.0.0"})) != DownloadFailed {
		t.Fatal("download error must propagate")
	}
	f.assertNotSwapped(t)
}

func TestHTTPDownloader404And500(t *testing.T) {
	for _, status := range []int{404, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		dl := HTTPDownloader(srv.Client(), srv.URL, "tok")
		_, err := dl(context.Background())
		srv.Close()
		if codeOf(err) != DownloadFailed {
			t.Errorf("status %d: err = %v, want DOWNLOAD_FAILED", status, err)
		}
	}
}

func TestSwapWindowsRenamesRunningExe(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent.exe")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := swapWindows(target, []byte("NEW")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "NEW" {
		t.Error("target not updated")
	}
	if b, _ := os.ReadFile(target + ".old"); string(b) != "OLD" {
		t.Error("running exe should be renamed to .old")
	}
}

func TestResolveReleasePublicKey(t *testing.T) {
	_, pemStr := keypairPEM(t)
	// PEM directly.
	if got := ResolveReleasePublicKey(func(string) string { return pemStr }); got != pemStr {
		t.Error("PEM key not resolved")
	}
	// base64-of-PEM.
	b64 := base64.StdEncoding.EncodeToString([]byte(pemStr))
	if got := ResolveReleasePublicKey(func(string) string { return b64 }); got != pemStr {
		t.Error("base64-of-PEM not decoded")
	}
	// placeholder -> "".
	ph := "-----BEGIN PUBLIC KEY-----\n" + placeholder + "\n-----END PUBLIC KEY-----"
	if got := ResolveReleasePublicKey(func(string) string { return ph }); got != "" {
		t.Error("placeholder must resolve to empty (fail-closed)")
	}
	// unset -> "".
	if got := ResolveReleasePublicKey(func(string) string { return "" }); got != "" {
		t.Error("unset must resolve to empty")
	}
}
