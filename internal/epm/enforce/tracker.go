// Package enforce implements Phase 6b's terminate-on-violation: the agent
// observing (via internal/epm/procmon) that an elevated launch spawned a
// child process its rule's Constraints.ChildProcess policy forbids, and
// killing that child.
//
// FRAMING THAT MUST APPEAR IN EVERY CUSTOMER-FACING DOCUMENT (copied from
// the plan verbatim, because it is the single most important fact about
// this package): without a kernel driver, nothing in this codebase can
// block a process before it runs. Every path through this package is
// observe-then-kill, never prevent-from-running. Measured kill latency
// depends entirely on which procmon backend is active underneath it —
// Windows 4688 ~200ms-3s, Linux netlink ~1-10ms, Linux/macOS polling
// ~250ms-1s — and malicious code can complete meaningful work inside any of
// those windows. Position this as containment and cleanup, never
// prevention.
//
// Deliberately a separate package from internal/epm (which declares
// Decision/Constraints/ChildProcessPolicy) and from internal/epm/procmon
// (which declares ProcessEvent and Monitor): this package imports both, and
// neither of them imports this one back — the same one-way dependency shape
// devicectx uses. Server (internal/epm/server.go) receives a Tracker
// through the small structural epm.ProcessTracker interface instead of a
// concrete *Tracker field, which is what keeps epm itself free of an import
// cycle back to this package.
package enforce

import (
	"sync"
	"time"

	"sentinelgo/internal/epm"
)

// rootInfo is what Tracker remembers about one elevated launch whose
// Constraints carry an enforceable ChildProcess policy.
type rootInfo struct {
	ruleID       string
	childPolicy  epm.ChildProcessPolicy
	childAllowed []string
	trackedAt    time.Time
}

// Tracker records the root PID of every successful elevated launch whose
// rule's Constraints.ChildProcess is Allowlist or Deny, and implements
// epm.ProcessTracker so a Server can be wired with WithProcessTracker(t).
// Roots with ChildInherit or ChildObserve are deliberately never recorded —
// see TrackRoot — since there is nothing for Enforcer to enforce for them
// (Observe means "record the tree, never act", which Enforcer already does
// implicitly by nature of being an observational process monitor; Inherit
// is legacy unconstrained behavior).
type Tracker struct {
	mu    sync.Mutex
	roots map[int]rootInfo
}

// NewTracker builds an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{roots: make(map[int]rootInfo)}
}

// TrackRoot implements epm.ProcessTracker.
func (t *Tracker) TrackRoot(pid int, decision epm.Decision) {
	c := decision.Outcome.Constraints
	if c.ChildProcess != epm.ChildAllowlist && c.ChildProcess != epm.ChildDeny {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roots[pid] = rootInfo{
		ruleID:       decision.RuleID,
		childPolicy:  c.ChildProcess,
		childAllowed: c.ChildAllowed,
		trackedAt:    time.Now().UTC(),
	}
}

// lookup returns the tracked root info for pid, if any.
func (t *Tracker) lookup(pid int) (rootInfo, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.roots[pid]
	return info, ok
}

// forget removes a root once it is no longer relevant (its own process
// exited — see Enforcer.handleExit).
func (t *Tracker) forget(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.roots, pid)
}

// rootCount reports how many roots are currently tracked — exposed for
// tests and diagnostics only.
func (t *Tracker) rootCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.roots)
}
