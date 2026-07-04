// Package backoff reproduces the Node agent's reconnect backoff
// (src/backoff.js): exponential with "half jitter" between 50% and 100% of the
// computed delay, and a hard cap. attempt starts at 1.
package backoff

import (
	"math"
	"math/rand"
	"time"
)

// Config mirrors the Node agent defaults: base 1s, cap 30s, factor 2.
type Config struct {
	BaseMs int
	MaxMs  int
	Factor float64
}

// Default returns the Node agent's default backoff configuration.
func Default() Config { return Config{BaseMs: 1000, MaxMs: 30000, Factor: 2} }

// Compute returns the delay for the given attempt (1-based). randFn returns a
// float in [0,1); pass nil to use the package rand source.
func Compute(attempt int, c Config, randFn func() float64) time.Duration {
	if c.BaseMs <= 0 {
		c.BaseMs = 1000
	}
	if c.MaxMs <= 0 {
		c.MaxMs = 30000
	}
	if c.Factor <= 0 {
		c.Factor = 2
	}
	if randFn == nil {
		randFn = rand.Float64
	}
	exp := math.Min(float64(c.MaxMs), float64(c.BaseMs)*math.Pow(c.Factor, math.Max(0, float64(attempt-1))))
	jittered := exp/2 + randFn()*(exp/2)
	return time.Duration(math.Round(jittered)) * time.Millisecond
}
