package builtins

import (
	"runtime"
	"testing"
)

func TestEmbeddedDefaultsLoadAndValidate(t *testing.T) {
	defs := Definitions()
	if len(defs) < 3 {
		t.Fatalf("expected >=3 embedded definitions, got %d", len(defs))
	}
	ids := map[string]bool{}
	for _, d := range defs {
		if err := d.Validate(); err != nil {
			t.Errorf("embedded def %q invalid: %v", d.ID, err)
		}
		ids[d.ID] = true
	}
	for _, want := range []string{"linux.net_dev", "linux.loadavg", "windows.net_stats", "darwin.net_ib"} {
		if !ids[want] {
			t.Errorf("missing embedded definition %q", want)
		}
	}
}

func TestEmbeddedHasHostApplicableDef(t *testing.T) {
	// Whatever OS the tests run on, at least one bundled default must apply, so a
	// freshly-installed agent has something to collect against a stock server.
	count := 0
	for _, d := range Definitions() {
		if d.Platform == runtime.GOOS {
			count++
		}
	}
	if count == 0 {
		t.Fatalf("no embedded definition applies to %s", runtime.GOOS)
	}
}
