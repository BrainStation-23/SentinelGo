package procmon

import (
	"context"
	"time"

	"sentinelgo/internal/epm"
)

// procInfo is a lightweight snapshot of one running process, independent of
// how it was collected (gopsutil on macOS, /proc on Linux's fallback path).
type procInfo struct {
	ParentPID   int
	ImagePath   string
	CommandLine string
}

// snapshotFunc returns the current set of running processes keyed by PID.
type snapshotFunc func() (map[int]procInfo, error)

// pollingMonitor diffs consecutive process snapshots on a fixed interval,
// emitting EventStart for PIDs that appeared and EventExit for PIDs that
// vanished since the previous snapshot. This is the shared, OS-agnostic
// core behind both monitor_darwin.go (gopsutil, primary — see the plan's
// explicit statement that EndpointSecurity/libproc are unreachable under
// the no-cgo constraint) and monitor_linux.go (gopsutil, fallback when the
// netlink connector cannot be opened, e.g. missing CAP_NET_ADMIN).
//
// A polling diff cannot see anything shorter-lived than the poll interval:
// a process that starts and exits between two ticks is invisible, and exit
// events never carry an exit code (nothing here ever called wait() on the
// process — it is simply observed to be gone). Both are accepted,
// documented limitations of this backend, not bugs.
type pollingMonitor struct {
	bus      *eventBus
	snapshot snapshotFunc
	interval time.Duration
	source   string

	cancel context.CancelFunc
	done   chan struct{}
	prev   map[int]procInfo
}

func newPollingMonitor(snapshot snapshotFunc, interval time.Duration, source string, capacity int) *pollingMonitor {
	return &pollingMonitor{bus: newEventBus(capacity), snapshot: snapshot, interval: interval, source: source}
}

func (m *pollingMonitor) Start() error {
	initial, err := m.snapshot()
	if err != nil {
		return err
	}
	m.prev = initial

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	go m.loop(ctx)
	return nil
}

func (m *pollingMonitor) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

// tick is exported to the package (unexported, lowercase) rather than
// folded into loop so tests can drive individual diff cycles deterministically
// instead of racing a real ticker.
func (m *pollingMonitor) tick() {
	cur, err := m.snapshot()
	if err != nil {
		return // transient failure; try again next tick, m.prev is unchanged
	}
	now := time.Now().UTC()
	for pid, info := range cur {
		if _, existed := m.prev[pid]; !existed {
			m.bus.send(newPollEvent(EventStart, now, pid, info, m.source))
		}
	}
	for pid, info := range m.prev {
		if _, still := cur[pid]; !still {
			m.bus.send(newPollEvent(EventExit, now, pid, info, m.source))
		}
	}
	m.prev = cur
}

func newPollEvent(kind EventKind, now time.Time, pid int, info procInfo, source string) ProcessEvent {
	have := HavePID
	if info.ParentPID != 0 {
		have |= HaveParentPID
	}
	if info.ImagePath != "" {
		have |= HaveImagePath
	}
	if info.CommandLine != "" {
		have |= HaveCommandLine
	}
	return ProcessEvent{
		Kind:        kind,
		ObservedAt:  now,
		PID:         pid,
		ParentPID:   info.ParentPID,
		ImagePath:   info.ImagePath,
		CommandLine: info.CommandLine,
		Elevated:    epm.TriUnknown, // polling never inspects tokens/privileges
		Source:      source,
		Have:        have,
	}
}

func (m *pollingMonitor) Events() <-chan ProcessEvent { return m.bus.Events() }

func (m *pollingMonitor) Dropped() uint64 { return m.bus.Dropped() }

func (m *pollingMonitor) Stop() {
	if m.cancel == nil {
		return
	}
	m.cancel()
	<-m.done
	m.bus.close()
}
