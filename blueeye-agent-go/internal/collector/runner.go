package collector

import (
	"context"
	"time"

	"github.com/gudlever-lgtm/blueeye-agent-go/internal/logx"
)

// PlatformRunner dispatches a definition's exec to the right runner: powershell
// bodies go to the persistent stream (Windows), everything else to OSRunner.
type PlatformRunner struct {
	OS     ExecRunner
	PS     ExecRunner // nil off-Windows / when no stream is configured
}

// Run selects the runner by exec mode.
func (p PlatformRunner) Run(ctx context.Context, ex Exec, timeout time.Duration, maxOutput int) ([]byte, error) {
	if ex.PowerShell != "" {
		if p.PS == nil {
			return nil, ErrPowerShellUnsupported
		}
		return p.PS.Run(ctx, ex, timeout, maxOutput)
	}
	return p.OS.Run(ctx, ex, timeout, maxOutput)
}

// DefaultRunner returns the production runner: OSRunner for command execs and a
// persistent PowerShell stream for powershell execs. The stream starts lazily on
// the first powershell collect, so on a host without PowerShell (e.g. Linux,
// where windows definitions don't apply anyway) nothing is spawned.
func DefaultRunner(logger *logx.Logger) PlatformRunner {
	return PlatformRunner{
		OS: OSRunner{},
		PS: NewStreamRunner(PowerShellFactory, logger),
	}
}
