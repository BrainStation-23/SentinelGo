package enforce

import (
	"context"
	"log"
	"path"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/epm/procmon"
)

// killFunc terminates pid. A package-level-style seam (passed into
// NewEnforcer rather than a package var, since Enforcer is normally
// constructed once per agent run) so tests never send a real signal to a
// real process.
type killFunc func(pid int) error

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithKillFunc overrides the platform kill primitive. Tests use this
// exclusively; production wiring (main_integration.go) supplies the real
// platform-specific implementation (see kill_windows.go/kill_unix.go).
func WithKillFunc(fn killFunc) Option {
	return func(e *Enforcer) { e.kill = fn }
}

// WithMaxKillsPerMinute overrides the kill-rate limiter's default (10),
// matching config.Config.GetEPMMaxKillsPerMinute.
func WithMaxKillsPerMinute(n int) Option {
	return func(e *Enforcer) { e.maxKillsPerMinute = n }
}

// WithClock overrides time.Now, for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(e *Enforcer) { e.now = now }
}

const defaultMaxKillsPerMinute = 10

// Enforcer consumes a procmon.Monitor's event stream and, ONLY when it was
// actually started (see Start — wiring code decides whether
// epm_process_monitor_mode=="enforce" at all, this type has no opinion of
// its own), kills a newly observed process descending from a Tracker-
// recorded root whose ChildProcess policy it violates.
//
// See the package doc comment for the framing that must accompany every
// description of what this type does: observe-then-kill, never
// prevent-from-running.
type Enforcer struct {
	tracker *Tracker
	monitor procmon.Monitor
	kill    killFunc
	now     func() time.Time

	maxKillsPerMinute int
	limiter           *killRateLimiter
	neverKill         neverKillList

	mu       sync.Mutex
	ancestry map[int]int // observed pid -> parent pid, pruned on exit

	cancel context.CancelFunc
	done   chan struct{}
}

// NewEnforcer builds an Enforcer. selfPID/selfAncestry seed the never-kill
// list — see neverKillList's doc comment. tracker and monitor are normally
// the same *Tracker passed to epm.WithProcessTracker and the same
// procmon.Monitor that was Start()-ed, so every root Server records is
// visible here and every process procmon observes is checked against it.
func NewEnforcer(tracker *Tracker, monitor procmon.Monitor, selfPID int, selfAncestry []int, opts ...Option) *Enforcer {
	e := &Enforcer{
		tracker:           tracker,
		monitor:           monitor,
		kill:              defaultKill,
		now:               time.Now,
		maxKillsPerMinute: defaultMaxKillsPerMinute,
		neverKill:         newNeverKillList(selfPID, selfAncestry),
		ancestry:          make(map[int]int),
	}
	for _, opt := range opts {
		opt(e)
	}
	e.limiter = newKillRateLimiter(e.maxKillsPerMinute, e.now)
	return e
}

// Start begins consuming monitor.Events() in a background goroutine. It
// does not itself call monitor.Start() — the caller owns the monitor's
// lifecycle (main_integration.go starts it once and may share it with other
// consumers), Enforcer only ever reads from the channel it exposes.
func (e *Enforcer) Start(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.done = make(chan struct{})
	go e.loop(runCtx)
}

// Stop stops consuming events. It does not stop the underlying monitor.
func (e *Enforcer) Stop() {
	if e.cancel == nil {
		return
	}
	e.cancel()
	<-e.done
}

func (e *Enforcer) loop(ctx context.Context) {
	defer close(e.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-e.monitor.Events():
			if !ok {
				return
			}
			e.handle(ev)
		}
	}
}

func (e *Enforcer) handle(ev procmon.ProcessEvent) {
	switch ev.Kind {
	case procmon.EventExit:
		e.handleExit(ev)
	case procmon.EventStart:
		e.handleStart(ev)
	}
}

func (e *Enforcer) handleExit(ev procmon.ProcessEvent) {
	e.mu.Lock()
	delete(e.ancestry, ev.PID)
	e.mu.Unlock()
	e.tracker.forget(ev.PID)
}

func (e *Enforcer) handleStart(ev procmon.ProcessEvent) {
	if ev.Have.Has(procmon.HaveParentPID) {
		e.mu.Lock()
		e.ancestry[ev.PID] = ev.ParentPID
		e.mu.Unlock()
	}

	root, ok := e.findRoot(ev.PID)
	if !ok {
		return
	}

	violated, reason := e.violates(root, ev)
	if !violated {
		return
	}

	e.terminate(ev, root, reason)
}

// findRoot walks the observed ancestry chain upward from pid looking for a
// tracked root. Bounded to a generous but finite number of hops so a
// corrupted or cyclic ancestry map (which should never happen, but this is
// exactly the kind of invariant worth defending defensively given the
// consequence of getting it wrong is an infinite loop in an enforcement
// hot path) cannot hang the loop goroutine.
const maxAncestryWalk = 64

func (e *Enforcer) findRoot(pid int) (rootInfo, bool) {
	if info, ok := e.tracker.lookup(pid); ok {
		return info, ok // the started process IS itself a tracked root's re-exec; not enforced against itself
	}

	e.mu.Lock()
	current := pid
	visited := make(map[int]bool)
	for i := 0; i < maxAncestryWalk; i++ {
		parent, known := e.ancestry[current]
		if !known || visited[current] {
			break
		}
		visited[current] = true
		if info, ok := e.tracker.lookup(parent); ok {
			e.mu.Unlock()
			return info, true
		}
		current = parent
	}
	e.mu.Unlock()
	return rootInfo{}, false
}

// violates reports whether ev breaks root's ChildProcess policy. A process
// whose ImagePath was never resolved (Have lacks HaveImagePath) is never
// treated as a violation — killing on unverifiable data would trade a
// policy miss for an availability risk, which is the wrong direction for an
// enforcement action with real, irreversible consequences.
func (e *Enforcer) violates(root rootInfo, ev procmon.ProcessEvent) (bool, string) {
	if !ev.Have.Has(procmon.HaveImagePath) {
		return false, ""
	}

	switch root.childPolicy {
	case epm.ChildDeny:
		return true, "rule " + root.ruleID + " forbids any child process"
	case epm.ChildAllowlist:
		if imagePathAllowed(ev.ImagePath, root.childAllowed) {
			return false, ""
		}
		return true, "rule " + root.ruleID + " child_allowed does not cover " + ev.ImagePath
	default:
		return false, ""
	}
}

func imagePathAllowed(imagePath string, patterns []string) bool {
	normalized := strings.ReplaceAll(imagePath, `\`, "/")
	for _, pat := range patterns {
		if ok, err := path.Match(strings.ReplaceAll(pat, `\`, "/"), normalized); err == nil && ok {
			return true
		}
	}
	return false
}

func (e *Enforcer) terminate(ev procmon.ProcessEvent, root rootInfo, reason string) {
	if e.neverKill.protects(ev.PID, ev.ImagePath) {
		log.Printf("epm: enforce: %s (pid %d, %s) would be killed but is on the never-kill list", reason, ev.PID, ev.ImagePath)
		return
	}

	if !e.limiter.allow() {
		log.Printf("epm: enforce: kill-rate limit reached; enforcement disabled for the remainder of this run")
		emergencylog.Record("epm", "terminate-on-violation disabled: kill-rate limit (%d/min) reached at pid %d (%s)",
			e.maxKillsPerMinute, ev.PID, ev.ImagePath)
		return
	}

	if err := e.kill(ev.PID); err != nil {
		log.Printf("epm: enforce: kill pid %d (%s) failed: %v", ev.PID, ev.ImagePath, err)
		return
	}

	log.Printf("epm: enforce: killed pid %d (%s): %s", ev.PID, ev.ImagePath, reason)
	emergencylog.Record("epm", "terminate-on-violation: killed pid %d (%s): %s", ev.PID, ev.ImagePath, reason)
}
