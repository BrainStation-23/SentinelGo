package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/models"
)

// These tests cover the bound added to what was an unbounded queue. Rows were
// previously deleted only on successful upload, so an agent whose backend was
// unreachable — or which the backend was permanently rejecting — grew this
// table until the endpoint's disk filled. See
// docs/telemetry/06-existing-code-observations.md item 2.

// makeSeverityLog builds a log with a specific syslog severity and a payload of
// a chosen size, so the row/byte/severity bounds can each be driven precisely.
func makeSeverityLog(id int, severity string, payloadBytes int) models.AuditLog {
	l := makeLog("test-source", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf("evt-%d", id))
	l.Severity = severity
	if payloadBytes > 0 {
		l.EventData = json.RawMessage(`{"k":"` + strings.Repeat("x", payloadBytes) + `"}`)
	} else {
		l.EventData = json.RawMessage(fmt.Sprintf(`{"n":%d}`, id))
	}
	return l
}

func insertN(t *testing.T, s *AuditLogStore, n int, severity string, payloadBytes int) {
	t.Helper()
	logs := make([]models.AuditLog, 0, n)
	for i := 0; i < n; i++ {
		logs = append(logs, makeSeverityLog(i, severity, payloadBytes))
	}
	if err := s.Insert(logs); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

// ── row bound ────────────────────────────────────────────────────────────────

func TestAuditRetention_RowLimit(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxRows: 100})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	insertN(t, s, 250, "6", 0)

	depth, err := s.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth > 100 {
		t.Errorf("queue depth = %d, want <= 100 — the row bound did not hold", depth)
	}

	dropped, err := s.TotalDropped()
	if err != nil {
		t.Fatalf("TotalDropped: %v", err)
	}
	if dropped == 0 {
		t.Error("rows were evicted but no drop counter was recorded — an audit " +
			"trail must never lose entries silently")
	}
	if int64(depth)+dropped < 250 {
		t.Errorf("depth(%d) + dropped(%d) < inserted(250): records went missing "+
			"without being counted", depth, dropped)
	}
}

// TestAuditRetention_EvictsLeastSevereFirst is the deterministic-eviction
// guarantee: routine noise is discarded before security-relevant records.
func TestAuditRetention_EvictsLeastSevereFirst(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxRows: 10})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Five criticals ("2") first, then a flood of debug ("7") behind them. The
	// criticals are the OLDEST rows, so a naive oldest-first policy would evict
	// exactly the records that matter.
	critical := make([]models.AuditLog, 0, 5)
	for i := 0; i < 5; i++ {
		critical = append(critical, makeSeverityLog(1000+i, "2", 0))
	}
	if err := s.Insert(critical); err != nil {
		t.Fatalf("insert criticals: %v", err)
	}
	insertN(t, s, 100, "7", 0)

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}

	var survivingCriticals int
	for _, r := range rows {
		if r.Log.Severity == "2" {
			survivingCriticals++
		}
	}
	if survivingCriticals != 5 {
		t.Errorf("%d of 5 critical records survived eviction, want all 5 — a "+
			"flood of debug events must not push out security records", survivingCriticals)
	}
}

// ── byte bound ───────────────────────────────────────────────────────────────

func TestAuditRetention_ByteLimit(t *testing.T) {
	const maxBytes = 64 * 1024

	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// ~2 KiB per row, 200 rows: roughly 400 KiB against a 64 KiB bound.
	insertN(t, s, 200, "6", 2048)

	total, err := s.TotalBytes()
	if err != nil {
		t.Fatalf("TotalBytes: %v", err)
	}
	if total > maxBytes {
		t.Errorf("queue holds %d bytes, want <= %d — the byte bound did not hold", total, maxBytes)
	}
	if total == 0 {
		t.Error("the byte bound emptied the queue entirely; it should evict down " +
			"to the limit, not discard everything")
	}

	stats, err := s.EvictionStats()
	if err != nil {
		t.Fatalf("EvictionStats: %v", err)
	}
	var sawBytes bool
	for _, c := range stats {
		if c.Reason == EvictReasonBytes && c.Dropped > 0 {
			sawBytes = true
		}
	}
	if !sawBytes {
		t.Errorf("no %q eviction counter recorded: %+v", EvictReasonBytes, stats)
	}
}

// TestAuditRetention_ByteLimitTerminatesOnOversizedRow pins that a single row
// larger than the whole bound cannot spin the eviction loop forever.
func TestAuditRetention_ByteLimitTerminatesOnOversizedRow(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxBytes: 512})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		insertN(t, s, 3, "6", 8192)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("byte-bound eviction did not terminate on rows larger than the bound")
	}
}

// ── age bound ────────────────────────────────────────────────────────────────

func TestAuditRetention_AgeLimit(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	insertN(t, s, 20, "6", 0)

	// Backdate half the rows past the bound. stored_at is written by SQLite's
	// CURRENT_TIMESTAMP, so the test writes the same "YYYY-MM-DD HH:MM:SS" form.
	old := time.Now().UTC().Add(-25 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec(
		"UPDATE audit_log_queue SET stored_at = ? WHERE id IN (SELECT id FROM audit_log_queue LIMIT 10)",
		old); err != nil {
		t.Fatalf("backdate rows: %v", err)
	}

	res, err := s.Prune()
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if res.ByAge != 10 {
		t.Errorf("age bound evicted %d rows, want 10", res.ByAge)
	}

	depth, err := s.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth != 10 {
		t.Errorf("queue depth = %d, want 10 — the in-date rows must survive", depth)
	}
}

// TestAuditRetention_AgeBoundAppliesToCriticalRecordsToo pins the deliberate
// asymmetry: severity protects a record from the row and byte bounds, but not
// from the age bound. Exempting criticals from age would let a permanently
// rejecting backend accumulate them without limit, which is the disk-fill the
// bound exists to prevent.
func TestAuditRetention_AgeBoundAppliesToCriticalRecordsToo(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	insertN(t, s, 5, "0", 0) // emergency

	old := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := s.db.Exec("UPDATE audit_log_queue SET stored_at = ?", old); err != nil {
		t.Fatalf("backdate rows: %v", err)
	}

	res, err := s.Prune()
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if res.ByAge != 5 {
		t.Errorf("age bound evicted %d rows, want 5", res.ByAge)
	}

	stats, err := s.EvictionStats()
	if err != nil {
		t.Fatalf("EvictionStats: %v", err)
	}
	var recorded bool
	for _, c := range stats {
		if c.Reason == EvictReasonAge {
			recorded = true
			if c.LastSeverity != "0" {
				t.Errorf("last_severity = %q, want %q — discarding emergency records "+
					"must be visible to an operator, not just counted", c.LastSeverity, "0")
			}
		}
	}
	if !recorded {
		t.Error("age eviction was not recorded in the drop counters")
	}
}

// ── durability ───────────────────────────────────────────────────────────────

// TestAuditRetention_CountersSurviveRestart is why the counters live in the
// database rather than in memory: the operator question is "has this device
// been losing audit records", and a process restart must not answer it "no".
func TestAuditRetention_CountersSurviveRestart(t *testing.T) {
	path := auditDBPath(t)

	s1, err := NewAuditLogStoreWithLimits(path, AuditLogLimits{MaxRows: 50})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	insertN(t, s1, 200, "6", 0)

	before, err := s1.TotalDropped()
	if err != nil {
		t.Fatalf("TotalDropped: %v", err)
	}
	if before == 0 {
		t.Fatal("expected evictions before restart")
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewAuditLogStoreWithLimits(path, AuditLogLimits{MaxRows: 50})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()

	after, err := s2.TotalDropped()
	if err != nil {
		t.Fatalf("TotalDropped after restart: %v", err)
	}
	if after != before {
		t.Errorf("drop counter = %d after restart, want %d — the record of lost "+
			"audit data must not reset with the process", after, before)
	}
}

// TestAuditRetention_QueuedRowsSurviveRestart pins that bounding the queue did
// not turn it into a cache: everything inside the bounds is still durable.
func TestAuditRetention_QueuedRowsSurviveRestart(t *testing.T) {
	path := auditDBPath(t)

	s1, err := NewAuditLogStoreWithLimits(path, AuditLogLimits{MaxRows: 1000})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	insertN(t, s1, 40, "3", 0)
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewAuditLogStoreWithLimits(path, AuditLogLimits{MaxRows: 1000})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()

	depth, err := s2.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth != 40 {
		t.Errorf("queue depth = %d after restart, want 40", depth)
	}
}

// TestAuditRetention_MigrationOnExistingDatabase covers the upgrade path: a v1
// database with rows already in it gains the counters table without losing
// anything.
func TestAuditRetention_MigrationOnExistingDatabase(t *testing.T) {
	path := auditDBPath(t)

	s1, err := NewAuditLogStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	insertN(t, s1, 25, "6", 0)
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewAuditLogStoreWithLimits(path, AuditLogLimits{MaxRows: 1000})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()

	depth, err := s2.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth != 25 {
		t.Errorf("queue depth = %d after migration, want 25 — existing rows must survive", depth)
	}

	// The byte bound must see the pre-existing rows' real size. This is why
	// size is computed from the text columns rather than an added column that
	// would default to zero for every row written before the upgrade.
	total, err := s2.TotalBytes()
	if err != nil {
		t.Fatalf("TotalBytes: %v", err)
	}
	if total == 0 {
		t.Error("rows written before the retention upgrade are accounted as zero " +
			"bytes, so the byte bound would not see the backlog it exists to bound")
	}
}

// ── outage and recovery ──────────────────────────────────────────────────────

// TestAuditRetention_BackendOutageDoesNotGrowWithoutBound simulates the actual
// failure: collection keeps running, nothing is ever uploaded, and the queue
// must stop growing instead of filling the disk.
func TestAuditRetention_BackendOutageDoesNotGrowWithoutBound(t *testing.T) {
	const maxRows = 500

	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxRows: maxRows})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// 20 collection cycles, no uploads at all — DeleteByIDs is never called.
	for cycle := 0; cycle < 20; cycle++ {
		logs := make([]models.AuditLog, 0, 100)
		for i := 0; i < 100; i++ {
			logs = append(logs, makeSeverityLog(cycle*1000+i, "6", 256))
		}
		if err := s.Insert(logs); err != nil {
			t.Fatalf("cycle %d insert: %v", cycle, err)
		}

		depth, err := s.Depth()
		if err != nil {
			t.Fatalf("Depth: %v", err)
		}
		if depth > maxRows {
			t.Fatalf("cycle %d: queue depth = %d, want <= %d — the queue is still "+
				"growing without bound during an outage", cycle, depth, maxRows)
		}
	}

	dropped, err := s.TotalDropped()
	if err != nil {
		t.Fatalf("TotalDropped: %v", err)
	}
	if dropped == 0 {
		t.Error("2000 records were collected into a 500-row queue but nothing was " +
			"counted as dropped")
	}
}

// TestAuditRetention_RecoveryAfterOutage pins that delivery semantics are
// unchanged: once the backend returns, whatever survived the bounds uploads and
// is deleted exactly as before.
func TestAuditRetention_RecoveryAfterOutage(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{MaxRows: 200})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Outage: five cycles collected, none uploaded.
	for cycle := 0; cycle < 5; cycle++ {
		insertN(t, s, 100, "6", 0)
	}

	depth, err := s.Depth()
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth == 0 {
		t.Fatal("the queue was emptied by the bounds; it should retain up to the limit")
	}

	// Recovery: drain exactly the way the uploader does.
	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != depth {
		t.Errorf("GetPending returned %d rows, want %d", len(rows), depth)
	}
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if err := s.DeleteByIDs(ids); err != nil {
		t.Fatalf("DeleteByIDs: %v", err)
	}

	remaining, err := s.Depth()
	if err != nil {
		t.Fatalf("Depth after drain: %v", err)
	}
	if remaining != 0 {
		t.Errorf("queue depth = %d after a successful drain, want 0", remaining)
	}

	// And collection continues normally afterwards.
	insertN(t, s, 10, "6", 0)
	after, err := s.Depth()
	if err != nil {
		t.Fatalf("Depth after recovery: %v", err)
	}
	if after != 10 {
		t.Errorf("queue depth = %d after post-recovery collection, want 10", after)
	}
}

// ── defaults ─────────────────────────────────────────────────────────────────

// TestAuditRetention_DefaultsAreBounded is the regression test for the original
// defect. A zero-valued limits struct must not mean "unbounded"; unbounded is
// precisely what is being removed.
func TestAuditRetention_DefaultsAreBounded(t *testing.T) {
	s, err := NewAuditLogStoreWithLimits(auditDBPath(t), AuditLogLimits{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.limits.MaxAge <= 0 || s.limits.MaxRows <= 0 || s.limits.MaxBytes <= 0 {
		t.Errorf("a zero limits struct produced an unbounded queue: %+v", s.limits)
	}

	d := DefaultAuditLogLimits()
	if d.MaxAge <= 0 || d.MaxRows <= 0 || d.MaxBytes <= 0 {
		t.Errorf("DefaultAuditLogLimits has an unbounded axis: %+v", d)
	}

	// NewAuditLogStore is the constructor every existing call site uses; it must
	// be bounded too, or the fix reaches nothing that ships.
	s2, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if s2.limits.MaxRows <= 0 {
		t.Error("NewAuditLogStore still creates an unbounded queue")
	}
}
