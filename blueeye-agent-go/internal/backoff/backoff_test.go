package backoff

import (
	"testing"
	"time"
)

func TestComputeBoundsAndCap(t *testing.T) {
	c := Default()
	// With randFn=0 -> lower bound = exp/2; randFn~1 -> ~exp.
	for attempt := 1; attempt <= 10; attempt++ {
		lo := Compute(attempt, c, func() float64 { return 0 })
		hi := Compute(attempt, c, func() float64 { return 0.999999 })
		if lo > hi {
			t.Fatalf("attempt %d: lo %v > hi %v", attempt, lo, hi)
		}
		// Never exceeds the cap (30s).
		if hi > 30*time.Second+time.Millisecond {
			t.Fatalf("attempt %d exceeded cap: %v", attempt, hi)
		}
		// Lower bound is at least half the cap once saturated.
		if attempt >= 6 && lo < 15*time.Second-time.Millisecond {
			t.Fatalf("attempt %d saturated lower bound too small: %v", attempt, lo)
		}
	}
}

func TestComputeGrows(t *testing.T) {
	c := Default()
	half := func(a int) time.Duration { return Compute(a, c, func() float64 { return 0 }) }
	if half(1) >= half(3) {
		t.Fatalf("backoff should grow: attempt1=%v attempt3=%v", half(1), half(3))
	}
	// attempt 1 lower bound = base/2 = 500ms.
	if got := half(1); got != 500*time.Millisecond {
		t.Fatalf("attempt1 lower bound = %v, want 500ms", got)
	}
}
