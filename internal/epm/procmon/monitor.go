// Package procmon implements Phase 6a's observational process monitoring:
// per-platform collectors that report process start/exit events for the EPM
// audit trail (and, in Phase 6b, for terminate-on-violation). This is
// observation only — see the plan's own framing, reproduced here because it
// matters for how every caller of this package must reason about it:
// without a kernel driver, NOTHING in this package can block a process
// before it runs. Every backend here is observe-after-the-fact; Phase 6b's
// enforcement is kill-after-launch, not prevent-launch.
//
// Deliberately a separate package from internal/epm, mirroring devicectx:
// this package imports OS-specific collection machinery (event log APIs,
// netlink, gopsutil); internal/epm never imports it back. Wiring a Monitor
// into the running agent happens in main_integration.go, alongside
// devicectx and BundleManager.
package procmon

import (
	"sync/atomic"
	"time"

	"sentinelgo/internal/epm"
)

// EventKind distinguishes a process starting from a process exiting.
type EventKind string

const (
	EventStart EventKind = "start"
	EventExit  EventKind = "exit"
)

// FieldMask records which ProcessEvent fields a given Source actually
// populated, so a caller never has to guess whether a zero value means
// "empty" or "this collector cannot provide it" — e.g. Windows's 4689
// (process exit) event carries no CommandLine, and a /proc read racing a
// short-lived Linux process may lose ImagePath/CommandLine to ENOENT
// entirely.
type FieldMask uint16

const (
	HavePID FieldMask = 1 << iota
	HaveParentPID
	HaveSessionID
	HaveUserID
	HaveImagePath
	HaveCommandLine
	HaveExitCode
	HaveElevated
)

// Has reports whether every bit in want is set in m.
func (m FieldMask) Has(want FieldMask) bool { return m&want == want }

// ProcessEvent is one observed process lifecycle transition.
type ProcessEvent struct {
	Kind       EventKind
	ObservedAt time.Time

	PID         int
	ParentPID   int
	SessionID   uint32
	UserID      string
	ImagePath   string
	CommandLine string
	ExitCode    int
	Elevated    epm.Tri

	// Source identifies which backend produced this event: "etw4688" |
	// "netlink" | "poll".
	Source string
	Have   FieldMask
}

// Monitor is the common interface every platform backend implements.
// Implementations must never let a stalled or slow consumer of Events()
// block the underlying OS callback/read loop — see eventBus below, which is
// the shared mechanism every backend uses to guarantee that.
type Monitor interface {
	// Start begins collection. It returns once the backend is ready to
	// deliver events (or has failed to start), not once collection ends.
	Start() error
	// Events is the channel new ProcessEvents are delivered on. Closed
	// after Stop.
	Events() <-chan ProcessEvent
	// Dropped is the number of events discarded because Events() was not
	// drained quickly enough (see eventBus.send). Monotonically increasing.
	Dropped() uint64
	Stop()
}

// eventBus is the shared "buffered, drop-with-a-counter-rather-than-stall"
// delivery mechanism every backend uses. An ETW/EvtSubscribe callback that
// blocks loses its whole session; a netlink reader that blocks overflows its
// socket receive buffer and silently loses kernel-side events too — in both
// cases the OS side is far less forgiving of a slow consumer than an
// ordinary Go channel send, which is why this drops instead of blocking.
type eventBus struct {
	ch      chan ProcessEvent
	dropped uint64
}

func newEventBus(capacity int) *eventBus {
	return &eventBus{ch: make(chan ProcessEvent, capacity)}
}

func (b *eventBus) send(ev ProcessEvent) {
	select {
	case b.ch <- ev:
	default:
		atomic.AddUint64(&b.dropped, 1)
	}
}

func (b *eventBus) Events() <-chan ProcessEvent { return b.ch }

func (b *eventBus) Dropped() uint64 { return atomic.LoadUint64(&b.dropped) }

func (b *eventBus) close() { close(b.ch) }
