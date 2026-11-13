package logging

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
)

// fakeCollector returns a fixed sequence of batches, then empty. It advances a
// simple counter checkpoint so runCollection's drain loop terminates.
type fakeCollector struct {
	batches [][]collector.RawLogEntry
	idx     int
	calls   int
}

func (f *fakeCollector) Collect(_ context.Context, _ collector.CheckpointData) ([]collector.RawLogEntry, collector.CheckpointData, error) {
	f.calls++
	if f.idx >= len(f.batches) {
		return nil, collector.CheckpointData{"n": int64(f.idx)}, nil
	}
	b := f.batches[f.idx]
	f.idx++
	return b, collector.CheckpointData{"n": int64(f.idx)}, nil
}

func (f *fakeCollector) Subscribe(_ context.Context, _ chan<- collector.RawLogEntry) error {
	return nil
}

func (f *fakeCollector) Sources() []string { return []string{"fake"} }

func makeBatch(prefix string, n int, ts time.Time) []collector.RawLogEntry {
	out := make([]collector.RawLogEntry, n)
	for i := 0; i < n; i++ {
		out[i] = collector.RawLogEntry{
			Timestamp:  ts,
			Source:     "fake",
			EventID:    fmt.Sprintf("%s-%d", prefix, i),
			RawMessage: fmt.Sprintf("%s message %d", prefix, i),
			Severity:   "error", // high: sent (#484)
			Metadata:   map[string]string{},
		}
	}
	return out
}

func newTestIntegration(t *testing.T, fc collector.Collector) *LoggingIntegration {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewAuditLogStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cpStore := NewCheckpointStore(dir)
	if err := cpStore.Load(); err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}

	return &LoggingIntegration{
		cfg:        &config.Config{DeviceID: "dev", LogFlushInterval: config.Duration(5 * time.Minute)},
		collector:  fc,
		parser:     parser.NewParser(),
		store:      st,
		checkpoint: cpStore,
	}
}

// TestRunCollection_DrainsAllBatches proves the burst-loss fix (H1/H6): a burst
// spanning multiple batches is fully drained into the store, not truncated to a
// single per-cycle cap.
func TestRunCollection_DrainsAllBatches(t *testing.T) {
	now := time.Now()
	fc := &fakeCollector{batches: [][]collector.RawLogEntry{
		makeBatch("a", 1500, now),
		makeBatch("b", 1500, now),
		makeBatch("c", 200, now),
	}}
	li := newTestIntegration(t, fc)

	if err := li.runCollection(context.Background()); err != nil {
		t.Fatalf("runCollection: %v", err)
	}

	pending, err := li.store.GetPending(0) // 0 = no limit
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(pending) != 3200 {
		t.Errorf("stored %d entries, want 3200 (burst must not be truncated)", len(pending))
	}
	if v, ok := li.checkpoint.Get()["n"]; !ok || v.(int64) != 3 {
		t.Errorf("checkpoint not advanced past all batches: %v", li.checkpoint.Get())
	}
}

// TestRunCollection_KeepsBacklogInWindow proves the downtime-loss fix (H1/H6):
// entries older than the flush interval but inside the retention window are
// NOT discarded. Previously a flush-interval filter dropped them after
// advancing the checkpoint past them. What is outside the retention window is
// covered by TestRunCollection_KeepsOnlyRetentionWindow (#437).
func TestRunCollection_KeepsBacklogInWindow(t *testing.T) {
	twoHoursAgo := time.Now().Add(-2 * time.Hour) // well outside the 5m flush window
	fc := &fakeCollector{batches: [][]collector.RawLogEntry{
		makeBatch("old", 50, twoHoursAgo),
	}}
	li := newTestIntegration(t, fc)

	if err := li.runCollection(context.Background()); err != nil {
		t.Fatalf("runCollection: %v", err)
	}

	pending, err := li.store.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(pending) != 50 {
		t.Errorf("stored %d old entries, want 50 (downtime backlog must be kept, not discarded)", len(pending))
	}
}

// TestRunCollection_SendsOnlyHighAndCritical: rows below high severity are
// counted and dropped, re-graded security events are kept, and the checkpoint
// still moves past everything (#484).
func TestRunCollection_SendsOnlyHighAndCritical(t *testing.T) {
	now := time.Now()
	entry := func(id, source, sev string) collector.RawLogEntry {
		return collector.RawLogEntry{Timestamp: now, Source: source, EventID: id, RawMessage: id, Severity: sev, Metadata: map[string]string{}}
	}
	batch := []collector.RawLogEntry{
		entry("a", "fake", "info"),
		entry("b", "fake", "notice"),
		entry("c", "fake", "warning"),
		entry("d", "fake", "err"),
		entry("e", "fake", "crit"),
		entry("4625", collector.SourceWindowsSecurity, "6"), // failed logon, logged as Information
		entry("1116", collector.SourceWindowsDefender, "4"), // malware detected, logged as Warning
		entry("4634", collector.SourceWindowsSecurity, "6"), // logoff: routine
	}
	li := newTestIntegration(t, &fakeCollector{batches: [][]collector.RawLogEntry{batch}})
	if err := li.runCollection(context.Background()); err != nil {
		t.Fatalf("runCollection: %v", err)
	}
	if got, want := pendingCount(t, li.store), 4; got != want {
		t.Errorf("queued %d rows, want %d (err, crit, 4625, 1116)", got, want)
	}
	if got, want := li.GetStatistics().DroppedLowSeverity, int64(4); got != want {
		t.Errorf("DroppedLowSeverity = %d, want %d", got, want)
	}
	if n, ok := collector.CheckpointInt64(collector.CheckpointData(li.checkpoint.Get()), "n"); !ok || n != 1 {
		t.Errorf("checkpoint n = %v, %v; want 1 (moved past the dropped rows)", n, ok)
	}
}
