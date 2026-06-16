package store

import (
	"testing"
	"time"

	"sentinelgo/internal/models"
)

// insertOld inserts a row directly with an explicit stored_at in the past, bypassing the
// CURRENT_TIMESTAMP default so age-based retention can be exercised deterministically.
func insertOld(t *testing.T, s *AuditLogStore, hash, eventType, agoModifier string) {
	t.Helper()
	_, err := s.db.Exec(`
		INSERT INTO audit_log_queue
			(log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data, stored_at)
		VALUES (?, 'dev-1', 'linux', 'v1', ?, 'SYSTEM_LOG', 'agent', 'low', '2024-01-01T00:00:00Z', '{}', datetime('now', ?))`,
		hash, eventType, agoModifier)
	if err != nil {
		t.Fatalf("insert old row: %v", err)
	}
}

func TestPruneByAge_RemovesOnlyOldRows(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// A fresh row (stored_at = now via Insert) and two old rows.
	if err := s.Insert([]models.AuditLog{makeLog("agent", "2024-06-01T00:00:00Z", "fresh")}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	insertOld(t, s, "h-old-1", "old1", "-10 days")
	insertOld(t, s, "h-old-2", "old2", "-8 days")

	removed, err := s.PruneByAge(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PruneByAge: %v", err)
	}
	if removed != 2 {
		t.Errorf("PruneByAge removed %d, want 2", removed)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 1 || rows[0].Log.EventType != "fresh" {
		t.Errorf("expected only the fresh row to remain, got %d rows", len(rows))
	}
}

func TestPruneByAge_ZeroIsNoOp(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	insertOld(t, s, "h-old", "old", "-100 days")
	removed, err := s.PruneByAge(0)
	if err != nil {
		t.Fatalf("PruneByAge(0): %v", err)
	}
	if removed != 0 {
		t.Errorf("PruneByAge(0) removed %d, want 0 (disabled)", removed)
	}
}

func TestPruneToMaxRows_KeepsNewest(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Insert 5 distinct rows in order; id is autoincrement so newest = highest id.
	for i := 1; i <= 5; i++ {
		ts := "2024-01-01T00:00:0" + string(rune('0'+i)) + "Z"
		if err := s.Insert([]models.AuditLog{makeLog("agent", ts, "evt")}); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	removed, err := s.PruneToMaxRows(3)
	if err != nil {
		t.Fatalf("PruneToMaxRows: %v", err)
	}
	if removed != 2 {
		t.Errorf("PruneToMaxRows removed %d, want 2", removed)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows after cap, got %d", len(rows))
	}
	// Oldest-first ordering: the survivors are the 3 newest by id (timestamps 03,04,05).
	if rows[0].Log.Timestamp != "2024-01-01T00:00:03Z" {
		t.Errorf("expected oldest survivor ts=...03Z, got %q", rows[0].Log.Timestamp)
	}
}

func TestPruneToMaxRows_UnderCapIsNoOp(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Insert([]models.AuditLog{
		makeLog("agent", "2024-01-01T00:00:01Z", "a"),
		makeLog("agent", "2024-01-01T00:00:02Z", "b"),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	removed, err := s.PruneToMaxRows(10)
	if err != nil {
		t.Fatalf("PruneToMaxRows: %v", err)
	}
	if removed != 0 {
		t.Errorf("PruneToMaxRows under cap removed %d, want 0", removed)
	}

	removed, err = s.PruneToMaxRows(0)
	if err != nil {
		t.Fatalf("PruneToMaxRows(0): %v", err)
	}
	if removed != 0 {
		t.Errorf("PruneToMaxRows(0) removed %d, want 0 (disabled)", removed)
	}
}

func TestDeadLetter_RecordsRows(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.DeadLetter(nil, "x"); err != nil {
		t.Errorf("DeadLetter(nil) should be a no-op, got: %v", err)
	}

	logs := []models.AuditLog{
		makeLog("agent", "2024-01-01T00:00:01Z", "a"),
		makeLog("agent", "2024-01-01T00:00:02Z", "b"),
	}
	if err := s.DeadLetter(logs, "HTTP 400 rejected"); err != nil {
		t.Fatalf("DeadLetter: %v", err)
	}

	n, err := s.DeadLetterCount()
	if err != nil {
		t.Fatalf("DeadLetterCount: %v", err)
	}
	if n != 2 {
		t.Errorf("dead-letter count = %d, want 2", n)
	}
}

func TestPruneDeadLetterByAge(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Fresh dead-letter row via DeadLetter (dropped_at = now).
	if err := s.DeadLetter([]models.AuditLog{makeLog("agent", "2024-06-01T00:00:00Z", "fresh")}, "r"); err != nil {
		t.Fatalf("DeadLetter: %v", err)
	}
	// An old dead-letter row.
	if _, err := s.db.Exec(`
		INSERT INTO audit_log_deadletter
			(log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data, reason, dropped_at)
		VALUES ('h','dev','linux','v1','old','SYSTEM_LOG','agent','low','2024-01-01T00:00:00Z','{}','r', datetime('now','-40 days'))`); err != nil {
		t.Fatalf("insert old dead-letter row: %v", err)
	}

	removed, err := s.PruneDeadLetterByAge(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PruneDeadLetterByAge: %v", err)
	}
	if removed != 1 {
		t.Errorf("PruneDeadLetterByAge removed %d, want 1", removed)
	}
	if n, _ := s.DeadLetterCount(); n != 1 {
		t.Errorf("dead-letter count after prune = %d, want 1", n)
	}
}

func TestMaintain_ReclaimsFreelist(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Insert a meaningful number of rows, then delete them all so pages land on the
	// freelist (auto_vacuum=incremental does not auto-return them; Maintain must).
	logs := make([]models.AuditLog, 500)
	for i := range logs {
		ts := time.Unix(int64(i), 0).UTC().Format(time.RFC3339)
		logs[i] = makeLog("agent", ts, "evt")
	}
	if err := s.Insert(logs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	if err := s.DeleteByIDs(ids); err != nil {
		t.Fatalf("DeleteByIDs: %v", err)
	}

	var freeBefore int
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&freeBefore); err != nil {
		t.Fatalf("freelist_count before: %v", err)
	}
	if freeBefore == 0 {
		t.Skip("no free pages accumulated; nothing to reclaim on this build")
	}

	if err := s.Maintain(); err != nil {
		t.Fatalf("Maintain: %v", err)
	}

	var freeAfter int
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&freeAfter); err != nil {
		t.Fatalf("freelist_count after: %v", err)
	}
	if freeAfter != 0 {
		t.Errorf("freelist_count after Maintain = %d, want 0 (freed back to OS)", freeAfter)
	}
}
