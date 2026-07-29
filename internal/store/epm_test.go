package store_test

import (
	"errors"
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

// TestEPMStore_DeleteRulesNotInEmptyErrors pins the fail-safe: an empty ID set
// must NOT be read as "the server sent zero rules". A malformed or truncated
// sync payload easily produces one, and because policy evaluation is
// default-deny, wiping the cache locks every user out of every elevation. The
// caller has to reach for PruneAll deliberately.
func TestEPMStore_DeleteRulesNotInEmptyErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		activeID []string
	}{
		{"nil", nil},
		{"empty slice", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openEPMStoreInMemory(t)
			if err := s.UpsertRules([]epm.PolicyRule{{ID: "rule-1", Decision: epm.DecisionAllow}}); err != nil {
				t.Fatalf("UpsertRules: %v", err)
			}

			err := s.DeleteRulesNotIn(tc.activeID)
			if !errors.Is(err, store.ErrEmptyActiveIDs) {
				t.Fatalf("DeleteRulesNotIn(%v) error = %v, want ErrEmptyActiveIDs", tc.activeID, err)
			}

			got, err := s.GetRules()
			if err != nil {
				t.Fatalf("GetRules: %v", err)
			}
			if len(got) != 1 {
				t.Errorf("rules must survive a rejected prune: got %d, want 1", len(got))
			}
		})
	}
}

func TestEPMStore_PruneAll(t *testing.T) {
	s := openEPMStoreInMemory(t)

	if err := s.UpsertRules([]epm.PolicyRule{
		{ID: "rule-1", Decision: epm.DecisionAllow},
		{ID: "rule-2", Decision: epm.DecisionDeny},
	}); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}
	if err := s.PruneAll(); err != nil {
		t.Fatalf("PruneAll: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 rules after PruneAll, got %d", len(got))
	}

	// PruneAll on an already-empty table is not an error.
	if err := s.PruneAll(); err != nil {
		t.Errorf("PruneAll on empty store: %v", err)
	}
}

// TestEPMStore_GetRulesOrderedByID pins the deterministic ordering that
// epm.Engine's tie-break depends on: without it, two rules of equal tier and
// priority resolve by whichever storage happened to return first, so the same
// request could be allowed on one agent boot and denied on the next.
func TestEPMStore_GetRulesOrderedByID(t *testing.T) {
	s := openEPMStoreInMemory(t)

	if err := s.UpsertRules([]epm.PolicyRule{
		{ID: "c-rule", Decision: epm.DecisionAllow},
		{ID: "a-rule", Decision: epm.DecisionAllow},
		{ID: "b-rule", Decision: epm.DecisionAllow},
	}); err != nil {
		t.Fatalf("UpsertRules: %v", err)
	}

	got, err := s.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	want := []string{"a-rule", "b-rule", "c-rule"}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("rule[%d].ID = %q, want %q", i, got[i].ID, id)
		}
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

func TestEPMStore_AuditLogPhase8FieldsRoundTrip(t *testing.T) {
	s := openEPMStoreInMemory(t)

	exitCode := 0
	retainUntil := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	entry := epm.AuditEntry{
		RequestID: "req-p8", UserID: "alice", Decision: epm.DecisionAllow,
		LaunchedAt: time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC),

		SchemaVersion:     2,
		Verdict:           epm.VerdictAllow,
		Mode:              epm.ModeSilent,
		BundleID:          "bundle-7",
		RuleVersion:       3,
		Specificity:       250,
		Publisher:         "Contoso Inc",
		CommandLine:       "tool.exe --flag",
		ProcessID:         4242,
		ParentPID:         100,
		ParentPath:        `C:\explorer.exe`,
		ExitCode:          &exitCode,
		Justification:     "approved via ticket",
		ApprovalID:        "appr-1",
		GrantID:           "grant-1",
		DeviceContext:     `{"os_type":"windows"}`,
		MatchedConditions: `["hash","user"]`,
		AgentVersion:      "1.2.3",
		RetainUntil:       &retainUntil,
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
	got := unsynced[0].Entry
	if got.Verdict != epm.VerdictAllow || got.Mode != epm.ModeSilent || got.BundleID != "bundle-7" ||
		got.RuleVersion != 3 || got.Specificity != 250 || got.Publisher != "Contoso Inc" ||
		got.CommandLine != "tool.exe --flag" || got.ProcessID != 4242 || got.ParentPID != 100 ||
		got.ParentPath != `C:\explorer.exe` || got.Justification != "approved via ticket" ||
		got.ApprovalID != "appr-1" || got.GrantID != "grant-1" || got.DeviceContext != `{"os_type":"windows"}` ||
		got.MatchedConditions != `["hash","user"]` || got.AgentVersion != "1.2.3" {
		t.Errorf("Phase 8 fields did not round-trip: %+v", got)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Errorf("ExitCode = %v, want pointer to 0 (a real exit code of 0 must survive, not collapse to the -1 sentinel)", got.ExitCode)
	}
	if got.RetainUntil == nil || !got.RetainUntil.Equal(retainUntil) {
		t.Errorf("RetainUntil = %v, want %v", got.RetainUntil, retainUntil)
	}
}

func TestEPMStore_AuditLogExitCodeNilStaysNilNotZero(t *testing.T) {
	s := openEPMStoreInMemory(t)

	entry := epm.AuditEntry{RequestID: "req-noexit", Decision: epm.DecisionDeny, LaunchedAt: time.Now()}
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
	if unsynced[0].Entry.ExitCode != nil {
		t.Errorf("ExitCode = %v, want nil (unknown) when the caller never set it", *unsynced[0].Entry.ExitCode)
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
