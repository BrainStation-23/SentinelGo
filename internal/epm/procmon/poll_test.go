package procmon

import (
	"errors"
	"testing"
	"time"
)

func drain(t *testing.T, ch <-chan ProcessEvent) []ProcessEvent {
	t.Helper()
	var events []ProcessEvent
	for {
		select {
		case ev := <-ch:
			events = append(events, ev)
		default:
			return events
		}
	}
}

func TestPollingMonitor_Tick_EmitsStartForNewPID(t *testing.T) {
	snapshots := []map[int]procInfo{
		{1: {ImagePath: "/bin/init"}},
		{1: {ImagePath: "/bin/init"}, 2: {ParentPID: 1, ImagePath: "/bin/sh", CommandLine: "sh -c foo"}},
	}
	i := 0
	m := newPollingMonitor(func() (map[int]procInfo, error) {
		snap := snapshots[i]
		if i < len(snapshots)-1 {
			i++
		}
		return snap, nil
	}, time.Hour, "poll", 16)

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer m.Stop()

	m.tick() // transitions from snapshot[0] to snapshot[1]

	events := drain(t, m.Events())
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Kind != EventStart || ev.PID != 2 || ev.ParentPID != 1 || ev.ImagePath != "/bin/sh" || ev.CommandLine != "sh -c foo" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if !ev.Have.Has(HavePID | HaveParentPID | HaveImagePath | HaveCommandLine) {
		t.Errorf("Have = %b, missing expected bits", ev.Have)
	}
	if ev.Have.Has(HaveExitCode) {
		t.Errorf("Have includes HaveExitCode, but polling never sets it")
	}
}

func TestPollingMonitor_Tick_EmitsExitForVanishedPID(t *testing.T) {
	snapshots := []map[int]procInfo{
		{1: {}, 2: {ImagePath: "/bin/sh"}},
		{1: {}},
	}
	i := 0
	m := newPollingMonitor(func() (map[int]procInfo, error) {
		snap := snapshots[i]
		if i < len(snapshots)-1 {
			i++
		}
		return snap, nil
	}, time.Hour, "poll", 16)

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer m.Stop()

	m.tick()

	events := drain(t, m.Events())
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Kind != EventExit || events[0].PID != 2 {
		t.Errorf("unexpected event: %+v", events[0])
	}
	if events[0].Have.Has(HaveExitCode) {
		t.Errorf("polling must never claim to know an exit code")
	}
}

func TestPollingMonitor_Tick_NoChangeEmitsNothing(t *testing.T) {
	snap := map[int]procInfo{1: {}, 2: {}}
	m := newPollingMonitor(func() (map[int]procInfo, error) { return snap, nil }, time.Hour, "poll", 16)
	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer m.Stop()

	m.tick()
	m.tick()

	if events := drain(t, m.Events()); len(events) != 0 {
		t.Errorf("got %d events for an unchanged snapshot, want 0: %+v", len(events), events)
	}
}

func TestPollingMonitor_Tick_TransientSnapshotErrorLeavesPrevUnchanged(t *testing.T) {
	calls := 0
	m := newPollingMonitor(func() (map[int]procInfo, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("transient failure")
		}
		return map[int]procInfo{1: {}}, nil
	}, time.Hour, "poll", 16)

	if err := m.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer m.Stop()

	m.tick() // calls=2, errors; m.prev must remain the initial {1:{}}

	if events := drain(t, m.Events()); len(events) != 0 {
		t.Errorf("got %d events from a failed tick, want 0: %+v", len(events), events)
	}

	m.tick() // calls=3, back to {1:{}} — no diff vs the still-intact prev
	if events := drain(t, m.Events()); len(events) != 0 {
		t.Errorf("got %d events after recovering to the same snapshot, want 0: %+v", len(events), events)
	}
}

func TestPollingMonitor_Start_PropagatesInitialSnapshotError(t *testing.T) {
	m := newPollingMonitor(func() (map[int]procInfo, error) {
		return nil, errors.New("boom")
	}, time.Hour, "poll", 16)
	if err := m.Start(); err == nil {
		t.Error("Start() error = nil, want the initial snapshot error propagated")
	}
}

func TestEventBus_DropsWhenFull(t *testing.T) {
	b := newEventBus(2)
	b.send(ProcessEvent{PID: 1})
	b.send(ProcessEvent{PID: 2})
	b.send(ProcessEvent{PID: 3}) // capacity exceeded, dropped

	if got := b.Dropped(); got != 1 {
		t.Errorf("Dropped() = %d, want 1", got)
	}
	if len(b.ch) != 2 {
		t.Errorf("channel len = %d, want 2", len(b.ch))
	}
}

func TestFieldMask_Has(t *testing.T) {
	m := HavePID | HaveImagePath
	if !m.Has(HavePID) {
		t.Error("Has(HavePID) = false, want true")
	}
	if m.Has(HaveExitCode) {
		t.Error("Has(HaveExitCode) = true, want false")
	}
	if !m.Has(HavePID | HaveImagePath) {
		t.Error("Has(HavePID|HaveImagePath) = false, want true")
	}
	if m.Has(HavePID | HaveExitCode) {
		t.Error("Has(HavePID|HaveExitCode) = true, want false (only PID is set of the two)")
	}
}
