package store_test

import (
	"testing"
	"time"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/store"
)

func openEPMStoreInMemory(t *testing.T) *store.EPMStore {
	t.Helper()
	s, err := store.NewEPMStore(":memory:")
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEPMStore_UpsertAndGetRules(t *testing.T) {
	s := openEPMStoreInMemory(t)

	rules := []epm.PolicyRule{
		{ID: "rule-1", AppPath: `C:\apps\tool.exe`, Decision: epm.DecisionAllow, Priority: 100},
		{ID: "rule-2", AppHash: "abc123", Decision: epm.DecisionDeny, Priority: 200},
	}
	if err := s.UpsertRules(rules); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetRules returned %d rules, want 2", len(got))
	}
}

func TestEPMStore_UpsertUpdatesExistingRule(t *testing.T) {
	s := openEPMStoreInMemory(t)

	if err := s.UpsertRules([]epm.PolicyRule{
		{ID: "rule-1", AppPath: "/tool", Decision: epm.DecisionDeny, Priority: 1},
	}); err != nil {
		t.Fatalf("first UpsertRules: %v", err)
	}
	if err := s.UpsertRules([]epm.PolicyRule{
		{ID: "rule-1", AppPath: "/tool", Decision: epm.DecisionAllow, Priority: 5},
	}); err != nil {
		t.Fatalf("second UpsertRules: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 rule after update, got %d", len(got))
	}
	if got[0].Decision != epm.DecisionAllow || got[0].Priority != 5 {
		t.Errorf("got %+v, want updated decision=allow priority=5", got[0])
	}
}

func TestEPMStore_DeleteRulesNotIn(t *testing.T) {
	s := openEPMStoreInMemory(t)

	rules := []epm.PolicyRule{
		{ID: "keep-1", Decision: epm.DecisionAllow},
		{ID: "keep-2", Decision: epm.DecisionAllow},
		{ID: "drop-me", Decision: epm.DecisionAllow},
	}
	if err := s.UpsertRules(rules); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}

	if err := s.DeleteRulesNotIn([]string{"keep-1", "keep-2"}); err != nil {
		t.Fatalf("DeleteRulesNotIn: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 rules after prune, got %d", len(got))
	}
	for _, r := range got {
		if r.ID == "drop-me" {
			t.Error("drop-me should have been pruned")
		}
	}
}

func TestEPMStore_DeleteRulesNotInEmptyWipesAll(t *testing.T) {
	s := openEPMStoreInMemory(t)

	if err := s.UpsertRules([]epm.PolicyRule{{ID: "rule-1", Decision: epm.DecisionAllow}}); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}
	if err := s.DeleteRulesNotIn(nil); err != nil {
		t.Fatalf("DeleteRulesNotIn(nil): %v", err)
	}
	got, _ := s.GetRules()
	if len(got) != 0 {
		t.Errorf("want 0 rules after empty prune, got %d", len(got))
	}
}

func TestEPMStore_ExpiresAtRoundTrip(t *testing.T) {
	s := openEPMStoreInMemory(t)

	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.UpsertRules([]epm.PolicyRule{
		{ID: "rule-1", Decision: epm.DecisionAllow, ExpiresAt: expires},
		{ID: "rule-2", Decision: epm.DecisionAllow},
	}); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	byID := map[string]time.Time{}
	for _, r := range got {
		byID[r.ID] = r.ExpiresAt
	}
	if !byID["rule-1"].Equal(expires) {
		t.Errorf("rule-1 ExpiresAt = %v, want %v", byID["rule-1"], expires)
	}
	if !byID["rule-2"].IsZero() {
		t.Errorf("rule-2 ExpiresAt should be zero (never expires), got %v", byID["rule-2"])
	}
}

func TestEPMStore_AuditLogInsertGetMarkSynced(t *testing.T) {
	s := openEPMStoreInMemory(t)

	entry := epm.AuditEntry{
		RequestID:  "req-1",
		UserID:     "alice",
		AppPath:    "/tool",
		AppHash:    "abc123",
		Decision:   epm.DecisionAllow,
		PolicyID:   "rule-1",
		LaunchedAt: time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC),
	}
	if err := s.InsertAuditLog(entry); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	unsynced, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs: %v", err)
	}
	if len(unsynced) != 1 {
		t.Fatalf("want 1 unsynced row, got %d", len(unsynced))
	}
	if unsynced[0].Entry.RequestID != "req-1" || unsynced[0].Entry.Decision != epm.DecisionAllow {
		t.Errorf("got %+v, want request-id req-1 / decision allow", unsynced[0].Entry)
	}

	if err := s.MarkAuditLogSynced([]int64{unsynced[0].ID}); err != nil {
		t.Fatalf("MarkAuditLogSynced: %v", err)
	}

	remaining, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs after sync: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("want 0 unsynced rows after MarkAuditLogSynced, got %d", len(remaining))
	}
}

func TestEPMStore_InsertAuditLogDuplicateRequestIDIgnored(t *testing.T) {
	s := openEPMStoreInMemory(t)

	entry := epm.AuditEntry{RequestID: "req-dup", UserID: "bob", Decision: epm.DecisionDeny, LaunchedAt: time.Now()}
	if err := s.InsertAuditLog(entry); err != nil {
		t.Fatalf("first InsertAuditLog: %v", err)
	}
	if err := s.InsertAuditLog(entry); err != nil {
		t.Fatalf("second InsertAuditLog (dup): %v", err)
	}

	got, err := s.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want 1 row after duplicate insert, got %d", len(got))
	}
}
