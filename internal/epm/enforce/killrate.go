package enforce

import (
	"sync"
	"time"
)

// killRateLimiter is the other non-negotiable safety valve alongside
// neverKillList: once maxPerMinute kills happen inside a rolling 60s
// window, it trips permanently for the remainder of the process's run
// (observation continues — only killing stops). It does not reset on its
// own; only a restart clears it. That is a deliberate one-way trip, not an
// oversight: a rule that is wrong enough to trigger the limiter once is
// wrong enough to keep triggering it, and a limiter that quietly resets
// would let a broken allowlist keep re-arming itself into a repeated
// self-inflicted DoS instead of loudly giving up and asking a human to look
// at the emergency log.
type killRateLimiter struct {
	maxPerMinute int

	mu      sync.Mutex
	tripped bool
	kills   []time.Time
	nowFn   func() time.Time
}

func newKillRateLimiter(maxPerMinute int, nowFn func() time.Time) *killRateLimiter {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &killRateLimiter{maxPerMinute: maxPerMinute, nowFn: nowFn}
}

// allow reports whether a kill may proceed right now, and records it if so.
// Once tripped, every subsequent call returns false regardless of how the
// window subsequently empties out.
func (l *killRateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.tripped {
		return false
	}

	now := l.nowFn()
	cutoff := now.Add(-1 * time.Minute)
	kept := l.kills[:0]
	for _, t := range l.kills {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.kills = kept

	if len(l.kills) >= l.maxPerMinute {
		l.tripped = true
		return false
	}

	l.kills = append(l.kills, now)
	return true
}

// isTripped reports whether the limiter has permanently disabled killing.
func (l *killRateLimiter) isTripped() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tripped
}
