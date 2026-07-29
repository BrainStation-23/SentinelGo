package store

import (
	"testing"
	"time"

	"sentinelgo/internal/epm"
)

// countAuditLogRows is a test-only helper reaching s.db directly — this
// file is package store (not store_test) specifically so it can verify a
// synced row is actually gone after PruneAuditLog, not merely absent from
// GetUnsyncedAuditLogs (which excludes synced rows regardless of whether
// they still exist).
func countAuditLogRows(t *testing.T, s *EPMStore) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM epm_audit_log`).Scan(&n); err != nil {
		t.Fatalf("count epm_audit_log rows: %v", err)
	}
	return n
}

func TestEPMStore_PruneAuditLog_OnlyDeletesSyncedRowsOlderThanCutoff(t *testing.T) {
	s, err := NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	mustInsert := func(id string, launchedAt time.Time) {
		t.Helper()
		if err := s.InsertAuditLog(epm.AuditEntry{RequestID: id, Decision: epm.DecisionAllow, LaunchedAt: launchedAt}); err != nil {
			t.Fatalf("InsertAuditLog(%s): %v", id, err)
		}
	}
	mustInsert("old-unsynced", old)     // never eligible: unsynced
	mustInsert("old-synced", old)       // eligible: synced and older than cutoff
	mustInsert("recent-synced", recent) // not eligible: synced but newer than cutoff

	unsynced, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs: %v", err)
	}
	var toSync []int64
	for _, row := range unsynced {
		if row.Entry.RequestID == "old-synced" || row.Entry.RequestID == "recent-synced" {
			toSync = append(toSync, row.ID)
		}
	}
	if len(toSync) != 2 {
		t.Fatalf("expected to mark 2 rows synced, found %d candidates", len(toSync))
	}
	if err := s.MarkAuditLogSynced(toSync); err != nil {
		t.Fatalf("MarkAuditLogSynced: %v", err)
	}

	if got := countAuditLogRows(t, s); got != 3 {
		t.Fatalf("row count before prune = %d, want 3", got)
	}

	if err := s.PruneAuditLog(cutoff); err != nil {
		t.Fatalf("PruneAuditLog: %v", err)
	}

	if got := countAuditLogRows(t, s); got != 2 {
		t.Errorf("row count after prune = %d, want 2 (only old-synced should have been deleted)", got)
	}

	remaining, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs after prune: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Entry.RequestID != "old-unsynced" {
		t.Errorf("unsynced rows after prune = %+v, want only old-unsynced", remaining)
	}
}

func TestEPMStore_PruneAuditLog_NoRowsIsHarmless(t *testing.T) {
	s, err := NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.PruneAuditLog(time.Now()); err != nil {
		t.Errorf("PruneAuditLog on empty store: %v", err)
	}
}

func TestEPMStore_PruneProcessEvents_OnlyDeletesSyncedRowsOlderThanCutoff(t *testing.T) {
	s, err := NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UTC().Format(time.RFC3339)
	recent := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).UTC().Format(time.RFC3339)
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	insert := func(observedAt string, synced int) {
		t.Helper()
		_, err := s.db.Exec(
			`INSERT INTO epm_process_events (observed_at, kind, pid, synced) VALUES (?, 'start', 1, ?)`,
			observedAt, synced,
		)
		if err != nil {
			t.Fatalf("insert epm_process_events: %v", err)
		}
	}
	insert(old, 0)    // never eligible: unsynced
	insert(old, 1)    // eligible
	insert(recent, 1) // not eligible: too new

	if err := s.PruneProcessEvents(cutoff); err != nil {
		t.Fatalf("PruneProcessEvents: %v", err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM epm_process_events`).Scan(&n); err != nil {
		t.Fatalf("count epm_process_events: %v", err)
	}
	if n != 2 {
		t.Errorf("row count after prune = %d, want 2", n)
	}
}

func TestEPMStore_Vacuum(t *testing.T) {
	s, err := NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Vacuum(); err != nil {
		t.Errorf("Vacuum: %v", err)
	}
}
