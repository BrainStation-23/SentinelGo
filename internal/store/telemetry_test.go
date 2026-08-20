package store_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/store"
)

func openStateStore(t *testing.T) *store.TelemetryStateStore {
	t.Helper()
	s, err := store.NewTelemetryStateStore(":memory:")
	if err != nil {
		t.Fatalf("NewTelemetryStateStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func openQueue(t *testing.T, limits store.OutboundLimits) *store.TelemetryOutboundStore {
	t.Helper()
	q, err := store.NewTelemetryOutboundStore(":memory:", limits)
	if err != nil {
		t.Fatalf("NewTelemetryOutboundStore: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

// ── section state ────────────────────────────────────────────────────────────

// TestSectionStateSurvivesRestart is the durability guarantee that makes an
// agent restart cheap. Without persisted state every restart looks like a first
// run and re-uploads the entire inventory.
func TestSectionStateSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/telemetry_state.db"

	s, err := store.NewTelemetryStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	if err := s.MarkCollected("identity", 1, "hash-abc", 1, "success", now); err != nil {
		t.Fatalf("MarkCollected: %v", err)
	}
	if err := s.MarkUploaded("identity", now); err != nil {
		t.Fatalf("MarkUploaded: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen, as a restarted agent would.
	s2, err := store.NewTelemetryStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()

	got, err := s2.Get("identity")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("section state did not survive restart")
	}
	if got.Hash != "hash-abc" {
		t.Errorf("hash = %q, want %q", got.Hash, "hash-abc")
	}
	if !got.LastReconciledAt.Equal(now) {
		t.Errorf("last reconciled = %v, want %v", got.LastReconciledAt, now)
	}
}

// TestMarkUploadedAdvancesReconcileClock verifies that delivery, not
// collection, is what resets the reconcile interval.
func TestMarkUploadedAdvancesReconcileClock(t *testing.T) {
	s := openStateStore(t)

	collected := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	if err := s.MarkCollected("os", 1, "h1", 1, "success", collected); err != nil {
		t.Fatalf("MarkCollected: %v", err)
	}

	got, err := s.Get("os")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastReconciledAt.IsZero() {
		t.Fatal("collection alone must not advance the reconcile clock")
	}

	uploaded := collected.Add(time.Minute)
	if err := s.MarkUploaded("os", uploaded); err != nil {
		t.Fatalf("MarkUploaded: %v", err)
	}
	got, _ = s.Get("os")
	if !got.LastReconciledAt.Equal(uploaded) {
		t.Errorf("reconcile clock = %v, want %v", got.LastReconciledAt, uploaded)
	}
}

// TestGetMissingSectionReturnsNil covers the first-run path.
func TestGetMissingSectionReturnsNil(t *testing.T) {
	s := openStateStore(t)
	got, err := s.Get("never-seen")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for an unknown section, got %+v", got)
	}
}

// TestResetForcesFullResync verifies the CLI escape hatch.
func TestResetForcesFullResync(t *testing.T) {
	s := openStateStore(t)
	now := time.Now().UTC()
	for _, name := range []string{"identity", "os", "network"} {
		if err := s.MarkCollected(name, 1, "h", 1, "success", now); err != nil {
			t.Fatalf("MarkCollected %s: %v", name, err)
		}
	}
	if err := s.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty state after reset, got %d entries", len(all))
	}
}

func TestCollectionGenerationSurvivesRestartAndReset(t *testing.T) {
	path := t.TempDir() + "/telemetry_state.db"
	s, err := store.NewTelemetryStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first, err := s.NextCollectionGeneration()
	if err != nil || first != 1 {
		t.Fatalf("first generation = %d, err=%v", first, err)
	}
	if err := s.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err = store.NewTelemetryStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s.Close() }()
	second, err := s.NextCollectionGeneration()
	if err != nil || second != 2 {
		t.Fatalf("generation after reset/restart = %d, err=%v; want 2", second, err)
	}
}

// ── outbound queue ───────────────────────────────────────────────────────────

func enqueueN(t *testing.T, q *store.TelemetryOutboundStore, n int, priority int, payload string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := q.Enqueue(store.OutboundMessage{
			SnapshotID: fmt.Sprintf("snap-%d", i),
			Section:    "processes",
			Class:      "inventory",
			Priority:   priority,
			Payload:    payload,
		}); err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}
}

// TestQueueEnforcesRowCap verifies the queue cannot grow without bound — the
// defect the existing audit-log queue still has.
func TestQueueEnforcesRowCap(t *testing.T) {
	q := openQueue(t, store.OutboundLimits{MaxRows: 10})
	enqueueN(t, q, 25, 50, "payload")

	depth, err := q.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth > 10 {
		t.Fatalf("queue depth %d exceeds cap of 10", depth)
	}
}

// TestQueueEnforcesByteCap verifies the byte bound independently of row count:
// ten enormous messages must be evicted just as surely as ten thousand small
// ones.
func TestQueueEnforcesByteCap(t *testing.T) {
	q := openQueue(t, store.OutboundLimits{MaxBytes: 5000})
	enqueueN(t, q, 20, 50, strings.Repeat("x", 1000))

	total, err := q.TotalBytes()
	if err != nil {
		t.Fatalf("TotalBytes: %v", err)
	}
	if total > 5000 {
		t.Fatalf("queue holds %d bytes, over the 5000 cap", total)
	}
}

// TestQueueEnforcesAgeCap verifies stale telemetry is discarded.
func TestQueueEnforcesAgeCap(t *testing.T) {
	q := openQueue(t, store.OutboundLimits{MaxAge: time.Hour})

	old := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := q.Enqueue(store.OutboundMessage{
		Section: "identity", Class: "inventory", Priority: 50,
		Payload: "stale", CreatedAt: old,
	}); err != nil {
		t.Fatalf("Enqueue stale: %v", err)
	}
	if _, err := q.Enqueue(store.OutboundMessage{
		Section: "identity", Class: "inventory", Priority: 50, Payload: "fresh",
	}); err != nil {
		t.Fatalf("Enqueue fresh: %v", err)
	}

	pending, err := q.GetPending(10)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	for _, m := range pending {
		if m.Payload == "stale" {
			t.Fatal("a message older than MaxAge should have been pruned")
		}
	}
}

// TestQueueEvictsLowestPriorityFirst is the important one: a burst of routine
// inventory must never push out an undelivered critical security event.
func TestQueueEvictsLowestPriorityFirst(t *testing.T) {
	q := openQueue(t, store.OutboundLimits{MaxRows: 5})

	// One critical event (priority 0), queued first.
	if _, err := q.Enqueue(store.OutboundMessage{
		SnapshotID: "critical-1",
		Section:    "security_posture",
		Class:      "event",
		Priority:   0,
		Payload:    "firewall_disabled",
	}); err != nil {
		t.Fatalf("Enqueue critical: %v", err)
	}

	// Then a flood of low-priority inventory.
	enqueueN(t, q, 30, 80, "routine-inventory")

	pending, err := q.GetPending(100)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}

	var foundCritical bool
	for _, m := range pending {
		if m.SnapshotID == "critical-1" {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Fatal("critical event was evicted by low-priority inventory; eviction must drop lowest priority first")
	}
	if len(pending) > 5 {
		t.Fatalf("queue depth %d exceeds cap of 5", len(pending))
	}
}

// TestGetPendingOrdersByPriority verifies urgent messages drain first.
func TestGetPendingOrdersByPriority(t *testing.T) {
	q := openQueue(t, store.DefaultOutboundLimits())

	for _, p := range []int{80, 0, 50, 10} {
		if _, err := q.Enqueue(store.OutboundMessage{
			SnapshotID: fmt.Sprintf("p%d", p),
			Section:    "identity",
			Class:      "inventory",
			Priority:   p,
			Payload:    "x",
		}); err != nil {
			t.Fatalf("Enqueue p=%d: %v", p, err)
		}
	}

	pending, err := q.GetPending(10)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	want := []string{"p0", "p10", "p50", "p80"}
	if len(pending) != len(want) {
		t.Fatalf("got %d messages, want %d", len(pending), len(want))
	}
	for i, id := range want {
		if pending[i].SnapshotID != id {
			t.Errorf("position %d = %q, want %q", i, pending[i].SnapshotID, id)
		}
	}
}

// TestQueueDeleteRemovesDelivered covers the drain path.
func TestQueueDeleteRemovesDelivered(t *testing.T) {
	q := openQueue(t, store.DefaultOutboundLimits())
	enqueueN(t, q, 3, 50, "payload")

	pending, err := q.GetPending(10)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	ids := []int64{pending[0].ID, pending[1].ID}
	if err := q.Delete(ids); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	depth, err := q.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth != 1 {
		t.Fatalf("depth after delete = %d, want 1", depth)
	}
}

// TestQueueEnqueueReportsEviction ensures loss is countable, never silent.
func TestQueueEnqueueReportsEviction(t *testing.T) {
	q := openQueue(t, store.OutboundLimits{MaxRows: 2})

	var totalEvicted int64
	for i := 0; i < 6; i++ {
		evicted, err := q.Enqueue(store.OutboundMessage{
			Section: "processes", Class: "inventory", Priority: 50, Payload: "x",
		})
		if err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
		totalEvicted += evicted
	}

	if totalEvicted == 0 {
		t.Fatal("eviction happened but was reported as zero; dropped telemetry must be countable")
	}
}

// TestQueueIncrementAttempts covers retry bookkeeping.
func TestQueueIncrementAttempts(t *testing.T) {
	q := openQueue(t, store.DefaultOutboundLimits())
	enqueueN(t, q, 1, 50, "payload")

	pending, _ := q.GetPending(1)
	if err := q.IncrementAttempts([]int64{pending[0].ID}); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}

	pending, _ = q.GetPending(1)
	if pending[0].Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", pending[0].Attempts)
	}
}
