package filedlp

// The fail-safe core of a hook that holds a file operation while it decides
// (#329): Linux fanotify permission events today. The kernel makes the
// opening process wait for our answer, so every rule here is about never
// leaving it waiting:
//
//   - every held operation gets exactly one answer;
//   - a timer answers with on_timeout (allow unless the policy says block)
//     when the decision isn't ready in time, and the late decision is dropped;
//   - when too many are already held, new ones are allowed at once (fail
//     open) and counted, so flooding the agent can't freeze the desktop;
//   - Stop answers everything still held with allow.
//
// It has no OS suffix and no syscalls: the hook supplies reply.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// permGate answers held operations.
type permGate struct {
	// reply answers one held operation and releases its handle; it is called
	// exactly once per submitted id.
	reply      func(id int, allow bool)
	maxPending int32

	mu      sync.Mutex
	held    map[int]func() // id → answers it with allow (Stop)
	stopped bool
	wg      sync.WaitGroup

	pending                                          atomic.Int32
	allowed, denied, timeouts, timeoutDenied, overld atomic.Uint64
}

// PermStats are a permission hook's counters, reported in the status so a
// fail-open bypass (a flood, slow scans) shows up.
type PermStats struct {
	Allowed       uint64 `json:"allowed"`
	Denied        uint64 `json:"denied"`
	Timeouts      uint64 `json:"timeouts"`       // answered by the timer
	TimeoutDenied uint64 `json:"timeout_denied"` // of which denied (on_timeout: block)
	Overloaded    uint64 `json:"overloaded"`     // allowed at once: too many held
	Pending       int32  `json:"pending"`
}

// BlockingHealth is a permission hook's state and counters.
type BlockingHealth struct {
	State string `json:"state"` // running, off, stopped:watchdog, unavailable:<reason>
	Marks int    `json:"marks"`
	PermStats
}

func newPermGate(maxPending int, reply func(id int, allow bool)) *permGate {
	return &permGate{reply: reply, maxPending: int32(min(maxPending, 1<<20)), held: map[int]func(){}} // #nosec G115 -- capped above
}

// allowNow answers at once (not the hook's business, our own process, a
// switch turned off).
func (g *permGate) allowNow(id int) {
	g.allowed.Add(1)
	g.reply(id, true)
}

// submit holds id while decide runs in its own goroutine. decide returns
// whether to block; its ctx ends when the timer has answered. After timeout
// the timer answers allow, or deny when timeoutBlock.
func (g *permGate) submit(id int, timeout time.Duration, timeoutBlock bool, decide func(ctx context.Context) bool) {
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		g.allowNow(id)
		return
	}
	if g.pending.Load() >= g.maxPending {
		g.mu.Unlock()
		g.overld.Add(1)
		g.allowNow(id)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	var answer func(allow, byTimer bool)
	g.held[id] = func() { answer(true, false) }
	g.pending.Add(1)
	g.wg.Add(2)
	g.mu.Unlock()

	answer = func(allow, byTimer bool) {
		once.Do(func() {
			g.mu.Lock()
			delete(g.held, id)
			g.mu.Unlock()
			cancel()
			g.pending.Add(-1)
			switch {
			case byTimer && !allow:
				g.timeouts.Add(1)
				g.timeoutDenied.Add(1)
				g.denied.Add(1)
			case byTimer:
				g.timeouts.Add(1)
				g.allowed.Add(1)
			case allow:
				g.allowed.Add(1)
			default:
				g.denied.Add(1)
			}
			g.reply(id, allow)
		})
	}
	go func() {
		defer g.wg.Done()
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-t.C:
			answer(!timeoutBlock, true)
		case <-ctx.Done():
		}
	}()
	go func() {
		defer g.wg.Done()
		block := func() (b bool) {
			defer func() {
				if recover() != nil {
					b = false // a panicking decision fails open
				}
			}()
			return decide(ctx)
		}()
		if ctx.Err() != nil {
			return // already answered (timer or Stop)
		}
		answer(!block, false)
	}()
}

// permStopWait bounds how long stop waits for decisions to notice; they
// have all been answered by then, so a stuck one only leaks a goroutine.
var permStopWait = 5 * time.Second

// stop answers everything still held with allow, then waits (bounded) for
// the decisions to return. Later submissions are allowed at once.
func (g *permGate) stop() {
	g.mu.Lock()
	g.stopped = true
	allow := make([]func(), 0, len(g.held))
	for _, a := range g.held {
		allow = append(allow, a)
	}
	g.mu.Unlock()
	for _, a := range allow {
		a()
	}
	done := make(chan struct{})
	go func() { g.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(permStopWait):
	}
}

func (g *permGate) stats() PermStats {
	return PermStats{Allowed: g.allowed.Load(), Denied: g.denied.Load(), Timeouts: g.timeouts.Load(),
		TimeoutDenied: g.timeoutDenied.Load(), Overloaded: g.overld.Load(), Pending: g.pending.Load()}
}
