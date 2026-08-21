package telemetry

import (
	"sync"
	"time"
)

// DefaultProbeTTL is how long a cached platform probe stays valid.
//
// It only has to outlive the gap between Capability and Collect inside one
// cycle — a few milliseconds in practice. It is deliberately far shorter than
// any collection interval, so a state change is never masked by the cache.
const DefaultProbeTTL = 30 * time.Second

// ProbeCache memoises one platform probe across the Capability/Collect pair of
// a single collection cycle.
//
// It exists because those two methods need the same answer. RunAll calls
// Capability first and skips Collect unless the state is supported, so a
// collector whose capability genuinely depends on the hardware (is there a TPM
// chip? is this machine UEFI?) has to run its probe twice per cycle — and for
// a probe that costs a PowerShell round-trip, that doubles the cost of the
// collector for no new information. Caching keeps the capability honest without
// paying for it twice.
//
// The zero value is not usable; construct with NewProbeCache.
type ProbeCache[T any] struct {
	mu     sync.Mutex
	val    T
	filled bool
	at     time.Time
	ttl    time.Duration
	now    func() time.Time
}

// NewProbeCache returns a cache holding a probe result for ttl. A non-positive
// ttl falls back to DefaultProbeTTL.
func NewProbeCache[T any](ttl time.Duration) *ProbeCache[T] {
	if ttl <= 0 {
		ttl = DefaultProbeTTL
	}
	return &ProbeCache[T]{ttl: ttl, now: time.Now}
}

// SetClock overrides the time source. Intended for tests.
func (c *ProbeCache[T]) SetClock(fn func() time.Time) {
	if fn == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = fn
}

// Get returns the cached value, running probe when the cache is empty or stale.
func (c *ProbeCache[T]) Get(probe func() T) T {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if c.filled && now.Sub(c.at) < c.ttl {
		return c.val
	}
	c.val = probe()
	c.filled = true
	c.at = now
	return c.val
}

// Invalidate drops any cached value, forcing the next Get to re-probe.
func (c *ProbeCache[T]) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filled = false
}
