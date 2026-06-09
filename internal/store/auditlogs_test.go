package store

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"sentinelgo/internal/models"
)

func auditDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit_test.db")
}

func makeLog(source, timestamp, eventType string) models.AuditLog {
	return models.AuditLog{
		Source:       source,
		Timestamp:    timestamp,
		EventType:    eventType,
		DeviceID:     "dev-1",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		LogCategory:  models.LogCategorySystem,
		Severity:     "low",
		EventData:    json.RawMessage(`{"key":"value"}`),
	}
}

// ── NewAuditLogStore ──────────────────────────────────────────────────────────

func TestAuditLogStore_CreatesDatabase(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore failed: %v", err)
	}
	defer func() { _ = s.Close() }()
}

func TestAuditLogStore_IdempotentSchema(t *testing.T) {
	path := auditDBPath(t)

	s1, err := NewAuditLogStore(path)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	_ = s1.Close()

	s2, err := NewAuditLogStore(path)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}
	_ = s2.Close()
}

func TestAuditLogStore_InvalidPath(t *testing.T) {
	_, err := NewAuditLogStore("/nonexistent/deep/path/audit.db")
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

// ── Insert ────────────────────────────────────────────────────────────────────

func TestAuditLogInsert_EmptySlice(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Insert(nil); err != nil {
		t.Errorf("Insert(nil) should be a no-op, got: %v", err)
	}
	if err := s.Insert([]models.AuditLog{}); err != nil {
		t.Errorf("Insert([]) should be a no-op, got: %v", err)
	}
}

func TestAuditLogInsert_SingleLog(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	l := makeLog("agent", "2024-01-01T00:00:00Z", "boot")
	if err := s.Insert([]models.AuditLog{l}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Log.EventType != "boot" {
		t.Errorf("expected EventType=boot, got %q", rows[0].Log.EventType)
	}
}

func TestAuditLogInsert_MultipleLogsInOneBatch(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	logs := []models.AuditLog{
		makeLog("agent", "2024-01-01T00:00:00Z", "boot"),
		makeLog("agent", "2024-01-01T00:01:00Z", "shutdown"),
		makeLog("agent", "2024-01-01T00:02:00Z", "login"),
	}
	if err := s.Insert(logs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("expected 3 rows, got %d", len(rows))
	}
}

// ── Deduplication ─────────────────────────────────────────────────────────────

func TestAuditLogInsert_DuplicateIsIgnored(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	l := makeLog("agent", "2024-01-01T00:00:00Z", "boot")
	if err := s.Insert([]models.AuditLog{l}); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	if err := s.Insert([]models.AuditLog{l}); err != nil {
		t.Fatalf("second Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 row after duplicate insert, got %d", len(rows))
	}
}

func TestAuditLogInsert_SameBatchDuplicate(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	l := makeLog("agent", "2024-01-01T00:00:00Z", "boot")
	if err := s.Insert([]models.AuditLog{l, l}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 row for same-batch duplicate, got %d", len(rows))
	}
}

func TestAuditLogInsert_DifferentTimestampIsNotDuplicate(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	l1 := makeLog("agent", "2024-01-01T00:00:00Z", "boot")
	l2 := makeLog("agent", "2024-01-01T00:01:00Z", "boot")
	if err := s.Insert([]models.AuditLog{l1, l2}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows for distinct timestamps, got %d", len(rows))
	}
}

// ── GetPending ────────────────────────────────────────────────────────────────

func TestAuditLogGetPending_ReturnsAllWhenLimitZero(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	logs := []models.AuditLog{
		makeLog("agent", "2024-01-01T00:00:01Z", "a"),
		makeLog("agent", "2024-01-01T00:00:02Z", "b"),
		makeLog("agent", "2024-01-01T00:00:03Z", "c"),
		makeLog("agent", "2024-01-01T00:00:04Z", "d"),
		makeLog("agent", "2024-01-01T00:00:05Z", "e"),
	}
	if err := s.Insert(logs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending(0): %v", err)
	}
	if len(rows) != 5 {
		t.Errorf("expected 5 rows with limit=0, got %d", len(rows))
	}
}

func TestAuditLogGetPending_RespectsLimit(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	for i := 0; i < 10; i++ {
		ts := "2024-01-01T00:00:" + twoDigitAudit(i) + "Z"
		if err := s.Insert([]models.AuditLog{makeLog("agent", ts, "evt")}); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	rows, err := s.GetPending(3)
	if err != nil {
		t.Fatalf("GetPending(3): %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("expected 3 rows with limit=3, got %d", len(rows))
	}
}

func TestAuditLogGetPending_EmptyStoreReturnsNil(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending on empty store: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows for empty store, got %d", len(rows))
	}
}

func TestAuditLogGetPending_RowIDsArePresent(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Insert([]models.AuditLog{makeLog("agent", "2024-01-01T00:00:00Z", "boot")}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if rows[0].ID <= 0 {
		t.Errorf("expected positive row ID, got %d", rows[0].ID)
	}
}

func TestAuditLogGetPending_EventDataRoundTrips(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	l := makeLog("agent", "2024-01-01T00:00:00Z", "boot")
	l.EventData = json.RawMessage(`{"uptime":120,"hostname":"box-1"}`)
	if err := s.Insert([]models.AuditLog{l}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rows[0].Log.EventData, &got); err != nil {
		t.Fatalf("unmarshal event_data: %v", err)
	}
	if got["hostname"] != "box-1" {
		t.Errorf("expected hostname=box-1, got %v", got["hostname"])
	}
}

// ── DeleteByIDs ───────────────────────────────────────────────────────────────

func TestAuditLogDeleteByIDs_EmptySlice(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.DeleteByIDs(nil); err != nil {
		t.Errorf("DeleteByIDs(nil) should be a no-op, got: %v", err)
	}
	if err := s.DeleteByIDs([]int64{}); err != nil {
		t.Errorf("DeleteByIDs([]) should be a no-op, got: %v", err)
	}
}

func TestAuditLogDeleteByIDs_RemovesTargetedRows(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	logs := []models.AuditLog{
		makeLog("agent", "2024-01-01T00:00:01Z", "a"),
		makeLog("agent", "2024-01-01T00:00:02Z", "b"),
		makeLog("agent", "2024-01-01T00:00:03Z", "c"),
	}
	if err := s.Insert(logs); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rows, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}

	toDelete := []int64{rows[0].ID, rows[1].ID}
	if err := s.DeleteByIDs(toDelete); err != nil {
		t.Fatalf("DeleteByIDs: %v", err)
	}

	remaining, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending after delete: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining row, got %d", len(remaining))
	}
	if remaining[0].Log.EventType != "c" {
		t.Errorf("expected remaining EventType=c, got %q", remaining[0].Log.EventType)
	}
}

func TestAuditLogDeleteByIDs_AllRows(t *testing.T) {
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

	remaining, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending after full delete: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 rows after deleting all, got %d", len(remaining))
	}
}

func TestAuditLogDeleteByIDs_NonExistentIDIsHarmless(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.DeleteByIDs([]int64{9999, 8888}); err != nil {
		t.Errorf("DeleteByIDs with unknown IDs should not error, got: %v", err)
	}
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

func TestAuditLogInsertGetDeleteLifecycle(t *testing.T) {
	s, err := NewAuditLogStore(auditDBPath(t))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Insert([]models.AuditLog{
		makeLog("agent", "2024-06-01T10:00:00Z", "boot"),
		makeLog("agent", "2024-06-01T10:01:00Z", "login"),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	pending, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}

	ids := []int64{pending[0].ID, pending[1].ID}
	if err := s.DeleteByIDs(ids); err != nil {
		t.Fatalf("DeleteByIDs: %v", err)
	}

	after, err := s.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending after upload: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("expected empty queue after upload, got %d rows", len(after))
	}
}

// ── normalizeEventData ────────────────────────────────────────────────────────

func TestNormalizeEventData_EmptyBecomesEmptyObject(t *testing.T) {
	out, err := normalizeEventData(nil)
	if err != nil {
		t.Fatalf("normalizeEventData(nil): %v", err)
	}
	if out != "{}" {
		t.Errorf("expected {}, got %q", out)
	}

	out, err = normalizeEventData(json.RawMessage{})
	if err != nil {
		t.Fatalf("normalizeEventData([]): %v", err)
	}
	if out != "{}" {
		t.Errorf("expected {}, got %q", out)
	}
}

func TestNormalizeEventData_ValidJSON(t *testing.T) {
	raw := json.RawMessage(`{"a":1}`)
	out, err := normalizeEventData(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != `{"a":1}` {
		t.Errorf("expected passthrough, got %q", out)
	}
}

func TestNormalizeEventData_InvalidJSONErrors(t *testing.T) {
	_, err := normalizeEventData(json.RawMessage(`{not valid}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// ── auditLogHash ──────────────────────────────────────────────────────────────

func TestAuditLogHash_Stability(t *testing.T) {
	l := makeLog("src", "2024-01-01T00:00:00Z", "boot")
	h1 := auditLogHash(&l)
	h2 := auditLogHash(&l)
	if h1 != h2 {
		t.Errorf("auditLogHash is not stable: %q vs %q", h1, h2)
	}
}

func TestAuditLogHash_DifferentSourceProducesDifferentHash(t *testing.T) {
	l1 := makeLog("src-a", "2024-01-01T00:00:00Z", "boot")
	l2 := makeLog("src-b", "2024-01-01T00:00:00Z", "boot")
	if auditLogHash(&l1) == auditLogHash(&l2) {
		t.Error("different Source should produce different hash")
	}
}

func TestAuditLogHash_DifferentTimestampProducesDifferentHash(t *testing.T) {
	l1 := makeLog("src", "2024-01-01T00:00:00Z", "boot")
	l2 := makeLog("src", "2024-01-01T00:01:00Z", "boot")
	if auditLogHash(&l1) == auditLogHash(&l2) {
		t.Error("different Timestamp should produce different hash")
	}
}

func TestAuditLogHash_DifferentEventTypeProducesDifferentHash(t *testing.T) {
	l1 := makeLog("src", "2024-01-01T00:00:00Z", "boot")
	l2 := makeLog("src", "2024-01-01T00:00:00Z", "shutdown")
	if auditLogHash(&l1) == auditLogHash(&l2) {
		t.Error("different EventType should produce different hash")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func twoDigitAudit(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
