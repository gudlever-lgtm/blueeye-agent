package collector

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// shDriver is a POSIX-sh equivalent of the PowerShell driver loop: it reads
// bodies from stdin, evaluates each at the run marker, and prints the matching
// end marker. It lets the stream machinery be tested without a Windows host.
const shDriver = `
acc=""
while IFS= read -r line; do
  case "$line" in
    "__BLUEEYE_RUN__ "*)
      token="${line#__BLUEEYE_RUN__ }"
      eval "$acc" 2>/dev/null
      printf '__BLUEEYE_END__ %s\n' "$token"
      acc=""
      ;;
    *)
      if [ -z "$acc" ]; then acc="$line"; else acc="$acc
$line"; fi
      ;;
  esac
done
`

func shFactory(ctx context.Context) (StreamProc, error) {
	return StartProc(exec.CommandContext(ctx, "sh", "-c", shDriver))
}

func psBody(s string) Exec { return Exec{PowerShell: s} }

func TestStreamCollectAndPersist(t *testing.T) {
	r := NewStreamRunner(shFactory, nil)
	defer r.Close()
	ctx := context.Background()

	out, err := r.Run(ctx, psBody("printf 'a: 1\nb: 2\n'"), 3*time.Second, DefaultMaxOutput)
	if err != nil {
		t.Fatalf("run1: %v", err)
	}
	if strings.TrimSpace(string(out)) != "a: 1\nb: 2" {
		t.Fatalf("run1 output = %q", out)
	}
	// Same session services a second request (persistence + per-request framing).
	out2, err := r.Run(ctx, psBody("echo hello-again"), 3*time.Second, DefaultMaxOutput)
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	if strings.TrimSpace(string(out2)) != "hello-again" {
		t.Fatalf("run2 output = %q", out2)
	}
	if r.seq != 2 {
		t.Fatalf("seq = %d, want 2", r.seq)
	}
}

func TestStreamPowerShellNotFound(t *testing.T) {
	failFactory := func(context.Context) (StreamProc, error) { return nil, errors.New("powershell.exe not found") }
	r := NewStreamRunner(failFactory, nil)
	_, err := r.Run(context.Background(), psBody("whatever"), time.Second, DefaultMaxOutput)
	if err == nil || !strings.Contains(err.Error(), "powershell unavailable") {
		t.Fatalf("want powershell-unavailable error, got %v", err)
	}
}

func TestStreamDiesMidCollectionThenRestarts(t *testing.T) {
	r := NewStreamRunner(shFactory, nil)
	defer r.Close()
	ctx := context.Background()
	// `exit` terminates the driver shell before it prints the end marker.
	_, err := r.Run(ctx, psBody("exit 0"), 3*time.Second, DefaultMaxOutput)
	if err == nil || !strings.Contains(err.Error(), "died mid-collection") {
		t.Fatalf("want stream-death error, got %v", err)
	}
	// Next call restarts the session and succeeds.
	out, err := r.Run(ctx, psBody("echo back"), 3*time.Second, DefaultMaxOutput)
	if err != nil || strings.TrimSpace(string(out)) != "back" {
		t.Fatalf("restart failed: out=%q err=%v", out, err)
	}
}

func TestStreamStallTimeoutKillsAndRestarts(t *testing.T) {
	r := NewStreamRunner(shFactory, nil)
	defer r.Close()
	ctx := context.Background()
	start := time.Now()
	_, err := r.Run(ctx, psBody("sleep 5"), 200*time.Millisecond, DefaultMaxOutput)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
	// Session restarts and works after a stall.
	out, err := r.Run(ctx, psBody("echo alive"), 3*time.Second, DefaultMaxOutput)
	if err != nil || strings.TrimSpace(string(out)) != "alive" {
		t.Fatalf("post-stall run failed: out=%q err=%v", out, err)
	}
}

func TestStreamOversizedOutputStaysFramed(t *testing.T) {
	r := NewStreamRunner(shFactory, nil)
	defer r.Close()
	ctx := context.Background()
	body := "i=0; while [ $i -lt 300 ]; do echo LINEXXXXXXXXXXXXXXXXXX; i=$((i+1)); done"
	_, err := r.Run(ctx, psBody(body), 5*time.Second, 128)
	if err != ErrOversizedOutput {
		t.Fatalf("want ErrOversizedOutput, got %v", err)
	}
	// The session drained through the end marker, so it's still usable.
	out, err := r.Run(ctx, psBody("echo still-here"), 3*time.Second, DefaultMaxOutput)
	if err != nil || strings.TrimSpace(string(out)) != "still-here" {
		t.Fatalf("session desynced after oversize: out=%q err=%v", out, err)
	}
}
