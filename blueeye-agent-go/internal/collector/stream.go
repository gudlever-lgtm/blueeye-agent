package collector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// The persistent PowerShell stream is ENGINE infrastructure: one long-lived
// powershell.exe process runs a small driver loop that reads collector script
// bodies from stdin, evaluates each, and frames the output with a per-request
// marker. The STREAM is code; what runs in it is DATA (definition exec.powershell
// bodies). It handles: PowerShell-not-found (start fails), the stream dying
// mid-collection (restart on next use), and stalled output (a per-collect
// timeout kills and restarts the session).
//
// The framing markers are shared with the driver below and with the test's sh
// driver, so the machinery is exercised without a Windows host.
const (
	runMarkerPrefix = "__BLUEEYE_RUN__ "
	endMarkerPrefix = "__BLUEEYE_END__ "
)

func runMarker(token string) string { return runMarkerPrefix + token }
func endMarker(token string) string { return endMarkerPrefix + token }

// PowerShellDriver is the loop passed to `powershell.exe -Command`. It reads
// bodies from stdin (freeing -Command from consuming stdin), evaluates each body
// at the run marker, and prints the matching end marker. Kept minimal and
// self-contained.
const PowerShellDriver = `
$ErrorActionPreference = 'Continue'
$acc = New-Object System.Text.StringBuilder
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($line -eq $null) { break }
  if ($line.StartsWith('` + runMarkerPrefix + `')) {
    $token = $line.Substring(` + `'` + runMarkerPrefix + `'.Length)
    try { Invoke-Expression $acc.ToString() | Out-String -Stream | ForEach-Object { Write-Output $_ } } catch { Write-Output ("ERROR: " + $_) }
    Write-Output ('` + endMarkerPrefix + `' + $token)
    $acc = New-Object System.Text.StringBuilder
  } else {
    [void]$acc.AppendLine($line)
  }
}
`

// StreamProc is a running interpreter process the StreamRunner talks to.
type StreamProc interface {
	Stdin() io.Writer
	Stdout() io.Reader
	Kill() error
}

// ProcFactory starts a fresh interpreter process bound to ctx (cancel kills it).
type ProcFactory func(ctx context.Context) (StreamProc, error)

type osProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (p *osProc) Stdin() io.Writer  { return p.stdin }
func (p *osProc) Stdout() io.Reader { return p.stdout }
func (p *osProc) Kill() error {
	if p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

// StartProc wires stdin/stdout pipes and starts cmd (stderr discarded so it can't
// corrupt the framed stdout). Exported for tests that supply their own driver.
func StartProc(cmd *exec.Cmd) (StreamProc, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &osProc{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

// PowerShellFactory starts a persistent powershell.exe running the driver. On a
// non-Windows host (or when PowerShell is absent) Start fails, which the runner
// surfaces as a start error — the "PowerShell not found" path.
func PowerShellFactory(ctx context.Context) (StreamProc, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-NoLogo", "-Command", PowerShellDriver)
	return StartProc(cmd)
}

type psSession struct {
	proc    StreamProc
	cancel  context.CancelFunc
	lines   chan string
	done    chan struct{}
	stopped chan struct{}
}

// StreamRunner runs powershell exec bodies through one persistent session,
// restarting it on death or stall. It satisfies ExecRunner. Calls are
// serialized (the session is a single pipe).
type StreamRunner struct {
	factory ProcFactory
	logger  *logx.Logger
	mu      sync.Mutex
	sess    *psSession
	seq     int
}

// NewStreamRunner builds a runner over the given process factory.
func NewStreamRunner(factory ProcFactory, logger *logx.Logger) *StreamRunner {
	if logger == nil {
		logger = logx.New(logx.Info)
	}
	return &StreamRunner{factory: factory, logger: logger}
}

func (s *StreamRunner) startLocked() error {
	ctx, cancel := context.WithCancel(context.Background())
	proc, err := s.factory(ctx)
	if err != nil {
		cancel()
		return err
	}
	sess := &psSession{
		proc: proc, cancel: cancel,
		lines: make(chan string, 256), done: make(chan struct{}), stopped: make(chan struct{}),
	}
	go func() {
		defer close(sess.done)
		sc := bufio.NewScanner(proc.Stdout())
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			select {
			case sess.lines <- sc.Text():
			case <-sess.stopped:
				return
			}
		}
	}()
	s.sess = sess
	return nil
}

// killLocked tears the session down so the next Run starts fresh.
func (s *StreamRunner) killLocked() {
	if s.sess == nil {
		return
	}
	close(s.sess.stopped)
	s.sess.cancel()
	_ = s.sess.proc.Kill()
	s.sess = nil
}

// Close stops the session (call on shutdown).
func (s *StreamRunner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killLocked()
}

// Run evaluates a powershell body in the persistent session and returns its
// framed stdout (capped at maxOutput). Errors: start failure (PowerShell not
// found), timeout (session killed + restarted), or stream death (restarted).
func (s *StreamRunner) Run(ctx context.Context, ex Exec, timeout time.Duration, maxOutput int) ([]byte, error) {
	if ex.PowerShell == "" {
		return nil, errors.New("collector: stream runner requires a powershell body")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sess == nil {
		if err := s.startLocked(); err != nil {
			return nil, fmt.Errorf("collector: powershell unavailable: %w", err)
		}
	}
	sess := s.sess
	s.seq++
	token := strconv.Itoa(s.seq)

	payload := ex.PowerShell + "\n" + runMarker(token) + "\n"
	if _, err := io.WriteString(sess.proc.Stdin(), payload); err != nil {
		s.killLocked()
		return nil, fmt.Errorf("collector: powershell stream write failed (session restarted): %w", err)
	}

	end := endMarker(token)
	var buf []byte
	truncated := false
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			s.killLocked()
			return nil, fmt.Errorf("collector: powershell stream timed out after %s (session restarted)", timeout)
		case <-sess.done:
			s.killLocked()
			return nil, errors.New("collector: powershell stream died mid-collection (session restarted)")
		case line := <-sess.lines:
			if line == end {
				if truncated {
					return nil, ErrOversizedOutput
				}
				return buf, nil
			}
			if !truncated {
				add := append([]byte(line), '\n')
				if len(buf)+len(add) > maxOutput {
					if room := maxOutput - len(buf); room > 0 {
						buf = append(buf, add[:room]...)
					}
					truncated = true
				} else {
					buf = append(buf, add...)
				}
			}
		}
	}
}
