package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/audit"
	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// Code classifies an upgrade failure (all fail-closed: no swap happens).
type Code string

const (
	DownloadFailed   Code = "DOWNLOAD_FAILED"
	NoPublicKey      Code = "NO_PUBLIC_KEY"
	NoManifest       Code = "NO_MANIFEST"
	BadManifest      Code = "BAD_MANIFEST"
	SignatureInvalid Code = "SIGNATURE_INVALID"
	ChecksumMismatch Code = "CHECKSUM_MISMATCH"
	VersionMismatch  Code = "VERSION_MISMATCH"
	SwapFailed       Code = "SWAP_FAILED"
)

// Error carries the failure code.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Msg) }

func fail(code Code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Download is the result of fetching the release binary + its signed manifest.
type Download struct {
	Data      []byte
	Manifest  string // base64 JSON (X-Release-Manifest)
	Signature string // base64 (X-Release-Signature)
	Status    int
}

// Downloader fetches the release. A non-2xx status must be returned as an error
// (so 404/500 fail-closed without touching disk).
type Downloader func(ctx context.Context) (*Download, error)

// manifest is the signed release descriptor (extra fields tolerated).
type manifest struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Command is the server's update command (subset).
type Command struct {
	Version   string
	Signature string // base64; presence marks a signed release
}

// Updater performs a verified self-replace.
type Updater struct {
	download  Downloader
	audit     *audit.Logger
	publicKey string
	exePath   string
	goos      string
	restart   func() error
	logger    *logx.Logger
}

// Config builds an Updater. Fields are injectable for tests.
type Config struct {
	Download  Downloader
	Audit     *audit.Logger
	PublicKey string
	ExePath   string      // defaults to os.Executable()
	GOOS      string      // defaults to runtime.GOOS
	Restart   func() error // defaults to a no-op-friendly restart
	Logger    *logx.Logger
}

// New builds an Updater with sensible defaults.
func New(c Config) *Updater {
	exe := c.ExePath
	if exe == "" {
		if p, err := os.Executable(); err == nil {
			exe = p
		}
	}
	goos := c.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	logger := c.Logger
	if logger == nil {
		logger = logx.New(logx.Info)
	}
	au := c.Audit
	if au == nil {
		au = audit.New("", nil)
	}
	restart := c.Restart
	if restart == nil {
		restart = func() error { return nil }
	}
	return &Updater{
		download: c.Download, audit: au, publicKey: c.PublicKey,
		exePath: exe, goos: goos, restart: restart, logger: logger,
	}
}

// HTTPDownloader is the default REST downloader for the release binary.
func HTTPDownloader(client *http.Client, url, token string) Downloader {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context) (*Download, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fail(DownloadFailed, "request: %v", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fail(DownloadFailed, "transport: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fail(DownloadFailed, "download HTTP %d", res.StatusCode)
		}
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fail(DownloadFailed, "read body: %v", err)
		}
		return &Download{
			Data:      data,
			Manifest:  res.Header.Get("X-Release-Manifest"),
			Signature: res.Header.Get("X-Release-Signature"),
			Status:    res.StatusCode,
		}, nil
	}
}

// Update downloads, verifies (fail-closed) and self-replaces, then restarts. The
// whole verify+swap runs inside a two-state audit (initiated → completed/failed).
// Nothing touches disk until every check passes.
func (u *Updater) Update(ctx context.Context, cmd Command) error {
	fields := map[string]any{"version": cmd.Version}
	err := u.audit.Action("upgrade", fields, func() error { return u.verifyAndSwap(ctx, cmd) })
	if err != nil {
		u.logger.Errorf("self-update failed: %v", err)
		return err
	}
	u.logger.Infof("self-update verified and applied (v%s); requesting restart.", cmd.Version)
	return u.restart()
}

func (u *Updater) verifyAndSwap(ctx context.Context, cmd Command) error {
	if u.download == nil {
		return fail(DownloadFailed, "no downloader configured")
	}
	dl, err := u.download(ctx)
	if err != nil {
		return err // already a coded *Error (incl. 404/500)
	}
	sum := sha256Hex(dl.Data)

	// Fail-closed: a signed release is mandatory. No key or no manifest ⇒ refuse.
	if u.publicKey == "" {
		return fail(NoPublicKey, "no release public key configured — refusing to install")
	}
	sigB64 := dl.Signature
	if sigB64 == "" {
		sigB64 = cmd.Signature
	}
	if dl.Manifest == "" || sigB64 == "" {
		return fail(NoManifest, "signed release is missing its manifest/signature")
	}
	manifestJSON, err := base64.StdEncoding.DecodeString(dl.Manifest)
	if err != nil {
		return fail(BadManifest, "manifest is not valid base64")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fail(BadManifest, "signature is not valid base64")
	}
	var mf manifest
	if err := json.Unmarshal(manifestJSON, &mf); err != nil {
		return fail(BadManifest, "manifest is not valid JSON")
	}
	if !VerifyManifest(manifestJSON, sig, u.publicKey) {
		return fail(SignatureInvalid, "release signature did not verify")
	}
	if mf.SHA256 != sum {
		return fail(ChecksumMismatch, "checksum mismatch (manifest %s, got %s)", mf.SHA256, sum)
	}
	if cmd.Version != "" && mf.Version != cmd.Version {
		return fail(VersionMismatch, "version mismatch (expected %s, got %s)", cmd.Version, mf.Version)
	}

	// Verified — only now touch disk.
	if err := u.swap(dl.Data); err != nil {
		return fail(SwapFailed, "%v", err)
	}
	return nil
}

// swap replaces the running binary. The collector-definitions cache lives in a
// separate directory and is never touched here.
func (u *Updater) swap(data []byte) error {
	if u.exePath == "" {
		return fmt.Errorf("no executable path")
	}
	if u.goos == "windows" {
		return swapWindows(u.exePath, data)
	}
	return swapUnix(u.exePath, data)
}

// swapUnix writes the new binary to a temp file in the same directory (same
// filesystem, for an atomic rename) and renames it over the target. On POSIX a
// running executable can be replaced by rename — the live process keeps the old
// inode until it re-execs.
func swapUnix(target string, data []byte) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".blueeye-upgrade-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, target)
}

// swapWindows cannot delete a running .exe, but it CAN rename it: move the
// running binary aside to <target>.old, then write the new binary in its place.
// The .old is cleaned up on the next start.
func swapWindows(target string, data []byte) error {
	old := target + ".old"
	_ = os.Remove(old) // clear a stale .old from a prior upgrade
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, old); err != nil {
			return err
		}
	}
	return os.WriteFile(target, data, 0o755)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SystemdRestart returns a restart func that asks systemd to restart the unit
// (the Linux production strategy; --no-block so the enqueued job survives this
// process being stopped).
func SystemdRestart(serviceName string) func() error {
	return func() error {
		return exec.Command("systemctl", "--no-block", "restart", serviceName).Run()
	}
}
