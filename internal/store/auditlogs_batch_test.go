package store

import (
	"fmt"
	"testing"
	"time"

	"sentinelgo/internal/models"
)

func newAuditStore(t *testing.T) *AuditLogStore {
	t.Helper()
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func insertN(t *testing.T, s *AuditLogStore, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.Insert([]models.AuditLog{makeLog("src", "2026-11-10T00:00:00Z", fmt.Sprintf("%s-%d", prefix, i))}); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
}

// A queue created before batch ids existed (schema v1) is upgraded in place
// and its rows are uploadable.
func TestAuditLogStore_MigratesV1Queue(t *testing.T) {
	path := auditDBPath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := Migrate(db, auditLogMigrations[:1]); err != nil {
		t.Fatalf("Migrate v1: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_log_queue (log_hash, device_id, os_type, agent_version, event_type, log_category, source, severity, timestamp, event_data)
		VALUES ('h1', 'd', 'linux', 'v', 'e', 'SYSTEM_LOG', 's', 'info', '2026-11-10T00:00:00Z', '{}')`); err != nil {
		t.Fatalf("insert v1 row: %v", err)
	}
	_ = db.Close()

	s, err := NewAuditLogStore(path)
	if err != nil {
		t.Fatalf("NewAuditLogStore on a v1 queue: %v", err)
	}
	defer func() { _ = s.Close() }()
	rows, err := s.GetUnbatched(10)
	if err != nil || len(rows) != 1 || rows[0].Hash != "h1" || rows[0].BatchID != "" {
		t.Fatalf("GetUnbatched = %+v, %v; want the v1 row, unbatched", rows, err)
	}
}

func TestAuditLogStore_BatchLifecycle(t *testing.T) {
	s := newAuditStore(t)
	insertN(t, s, "a", 5)

	if rows, err := s.GetOpenBatch(); err != nil || len(rows) != 0 {
		t.Fatalf("GetOpenBatch on a fresh queue = %d rows, %v", len(rows), err)
	}
	rows, err := s.GetUnbatched(3)
	if err != nil || len(rows) != 3 {
		t.Fatalf("GetUnbatched(3) = %d rows, %v", len(rows), err)
	}
	if err := s.AssignBatch([]int64{rows[0].ID, rows[1].ID, rows[2].ID}, "batch-1"); err != nil {
		t.Fatalf("AssignBatch: %v", err)
	}

	open, err := s.GetOpenBatch()
	if err != nil || len(open) != 3 || open[0].BatchID != "batch-1" || open[0].Hash == "" {
		t.Fatalf("GetOpenBatch = %+v, %v; want the 3 rows of batch-1", open, err)
	}
	if rest, _ := s.GetUnbatched(10); len(rest) != 2 {
		t.Errorf("unbatched rows = %d, want 2", len(rest))
	}

	if err := s.CompleteBatch(open, time.Now()); err != nil {
		t.Fatalf("CompleteBatch: %v", err)
	}
	if open, _ := s.GetOpenBatch(); len(open) != 0 {
		t.Errorf("batch-1 still open after CompleteBatch")
	}
	if all, _ := s.GetPending(0); len(all) != 2 {
		t.Errorf("pending rows = %d, want 2", len(all))
	}

	// The uploaded rows are not queued again when collected again.
	insertN(t, s, "a", 5)
	if all, _ := s.GetPending(0); len(all) != 2 {
		t.Errorf("pending rows after re-collecting = %d, want 2 (uploaded ones skipped)", len(all))
	}
}

func TestAuditLogStore_PruneUploaded(t *testing.T) {
	s := newAuditStore(t)
	insertN(t, s, "p", 2)
	rows, _ := s.GetPending(0)
	if err := s.CompleteBatch(rows, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatalf("CompleteBatch: %v", err)
	}
	if err := s.PruneUploaded(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatalf("PruneUploaded: %v", err)
	}
	// Forgotten after a day: the same events can be queued again.
	insertN(t, s, "p", 2)
	if all, _ := s.GetPending(0); len(all) != 2 {
		t.Errorf("pending rows = %d, want 2 after the hashes expired", len(all))
	}
}
