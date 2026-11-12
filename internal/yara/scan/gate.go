package scan

import (
	"context"
	"sync"
	"time"

	"sentinelgo/internal/yara"
)

// Priorities for the scan worker (#418). The YARA pool has one worker, so
// whoever holds the gate has it: an on-demand scan (an admin is waiting)
// goes first, then on-write scans (a new file, maybe a dropped tool), then
// the scheduled scan, which is checkpointed and doesn't mind waiting.
type priority int

const (
	prioScheduled priority = iota
	prioOnWrite
	prioOnDemand
	numPriorities
)

// onWriteShare is how often on-write scans may take a turn while an
// on-demand scan runs: one file per interval, so the on-demand scan keeps
// almost all of the worker and on-write files are never stuck behind it
// for hours.
const onWriteShare = time.Second

// gate hands the scan worker to one file scan at a time, by priority.
type gate struct {
	mu          sync.Mutex
	busy        bool
	waiting     [numPriorities]int
	changed     chan struct{} // closed and replaced on every change
	demand      bool          // an on-demand scan is running
	lastOnWrite time.Time
	now         func() time.Time
	share       time.Duration
}

func newGate() *gate {
	return &gate{changed: make(chan struct{}), now: time.Now, share: onWriteShare}
}

// acquire waits for the worker. It fails only when ctx ends.
func (g *gate) acquire(ctx context.Context, p priority) error {
	g.mu.Lock()
	g.waiting[p]++
	for {
		wait, ok := g.admit(p)
		if ok {
			g.waiting[p]--
			g.busy = true
			if p == prioOnWrite {
				g.lastOnWrite = g.now()
			}
			g.mu.Unlock()
			return nil
		}
		ch := g.changed
		g.mu.Unlock()
		var t *time.Timer
		var timer <-chan time.Time
		if wait > 0 {
			t = time.NewTimer(wait)
			timer = t.C
		}
		var done bool
		select {
		case <-ch:
		case <-timer:
		case <-ctx.Done():
			done = true
		}
		if t != nil {
			t.Stop()
		}
		if done {
			g.mu.Lock()
			g.waiting[p]--
			g.signal()
			g.mu.Unlock()
			return context.Cause(ctx)
		}
		g.mu.Lock()
	}
}

// admit reports whether p may take the worker now, or how long to wait
// before asking again (0: until something changes). g.mu is held.
func (g *gate) admit(p priority) (time.Duration, bool) {
	if g.busy {
		return 0, false
	}
	for q := p + 1; q < numPriorities; q++ {
		if g.waiting[q] > 0 {
			return 0, false
		}
	}
	if p == prioOnWrite && g.demand {
		if d := g.share - g.now().Sub(g.lastOnWrite); d > 0 {
			return d, false
		}
	}
	return 0, true
}

// release gives the worker back.
func (g *gate) release() {
	g.mu.Lock()
	g.busy = false
	g.signal()
	g.mu.Unlock()
}

// setDemand records whether an on-demand scan runs.
func (g *gate) setDemand(on bool) {
	g.mu.Lock()
	g.demand = on
	g.signal()
	g.mu.Unlock()
}

func (g *gate) signal() {
	close(g.changed)
	g.changed = make(chan struct{})
}

func prioOf(trigger string) priority {
	switch trigger {
	case yara.TriggerOnDemand:
		return prioOnDemand
	case yara.TriggerOnWrite:
		return prioOnWrite
	}
	return prioScheduled
}
