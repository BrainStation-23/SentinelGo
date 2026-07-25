package native

// End-to-end integration test for the EPM pipeline built in Phases 0-4:
// remote task delivery -> native handler -> local SQLite persistence ->
// policy engine evaluation -> audit logging -> sync-readiness query. This is
// the platform-agnostic core every _<os>.go enforcement layer (pipe_windows.go,
// socket_darwin.go, socket_linux.go) builds on: each of them resolves an
// ElevationRequest, calls Engine.Evaluate against rules loaded from the same
// EPMStore, and logs the outcome via the same Auditor — exactly what this
// test drives directly, without needing any OS-specific session/token/launch
// API. It therefore runs identically on every platform, including this one.

import (
	"context"
	"path/filepath"
	"testing"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestEPMEndToEnd_PolicySyncEvaluateAudit(t *testing.T) {
	cfg := testEPMCfg(t)

	// 1. Simulate the backend delivering an epm-policy-sync task, exactly as
	// it would arrive via agent_get_tasks: a hash-based allow rule, a
	// publisher-based allow rule, and an explicit low-priority deny wildcard
	// (so unmatched apps are denied via a real rule, not just engine default).
	payload := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "allow-by-hash", "app_hash": "deadbeef", "decision": "allow", "priority": 300},
			{"id": "allow-acme-publisher", "publisher": "Acme Inc", "decision": "allow", "priority": 200},
			{"id": "deny-wildcard", "decision": "deny", "priority": 0},
		},
	}

	h := &epmPolicySyncHandler{}
	note, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: payload})
	if err != nil {
		t.Fatalf("epm-policy-sync Run: %v", err)
	}
	if note == "" {
		t.Error("expected a non-empty status note")
	}

	// 2. Open the same store an enforcement layer would (RuleProvider) and
	// load the rules the sync just persisted.
	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("open EPM store: %v", err)
	}
	defer func() { _ = st.Close() }()

	rules, err := st.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 persisted rules, got %d", len(rules))
	}

	// 3. Evaluate exactly as an enforcement layer's evaluateAndLaunch would:
	// build an Engine fresh from the live rule set for each request.
	engine := epm.NewEngine(rules)

	allowByHash := engine.Evaluate(epm.ElevationRequest{
		RequestID: "req-1", UserID: "alice", AppPath: "/opt/tool", AppHash: "deadbeef",
	})
	if !allowByHash.Allowed || allowByHash.PolicyID != "allow-by-hash" {
		t.Errorf("hash-matched request should be allowed by allow-by-hash, got %+v", allowByHash)
	}

	allowByPublisher := engine.Evaluate(epm.ElevationRequest{
		RequestID: "req-2", UserID: "alice", AppPath: "/opt/other-tool", Publisher: "Acme Inc",
	})
	if !allowByPublisher.Allowed || allowByPublisher.PolicyID != "allow-acme-publisher" {
		t.Errorf("publisher-matched request should be allowed by allow-acme-publisher, got %+v", allowByPublisher)
	}

	denied := engine.Evaluate(epm.ElevationRequest{
		RequestID: "req-3", UserID: "alice", AppPath: "/opt/unapproved-tool",
	})
	if denied.Allowed {
		t.Errorf("unmatched request should be denied by deny-wildcard, got %+v", denied)
	}

	// 4. Audit all three outcomes through the real Auditor -> EPMStore path,
	// exactly as an enforcement layer's audit() method would.
	auditor := epm.NewAuditor(st)
	cases := []struct {
		req      epm.ElevationRequest
		decision epm.ElevationResponse
	}{
		{epm.ElevationRequest{RequestID: "req-1", UserID: "alice", AppPath: "/opt/tool", AppHash: "deadbeef"}, allowByHash},
		{epm.ElevationRequest{RequestID: "req-2", UserID: "alice", AppPath: "/opt/other-tool", Publisher: "Acme Inc"}, allowByPublisher},
		{epm.ElevationRequest{RequestID: "req-3", UserID: "alice", AppPath: "/opt/unapproved-tool"}, denied},
	}
	for _, c := range cases {
		decision := epm.DecisionDeny
		if c.decision.Allowed {
			decision = epm.DecisionAllow
		}
		entry := epm.AuditEntry{
			RequestID: c.req.RequestID,
			UserID:    c.req.UserID,
			AppPath:   c.req.AppPath,
			AppHash:   c.req.AppHash,
			Decision:  decision,
			PolicyID:  c.decision.PolicyID,
		}
		if err := auditor.Log(entry); err != nil {
			t.Fatalf("audit log %s: %v", c.req.RequestID, err)
		}
	}

	// 5. Verify the audit trail is queryable as unsynced (exactly what
	// internal/logging.UploadEPMAuditRows would drain) and transitions to
	// synced correctly — the same round trip Phase 4's audit upload task
	// performs.
	unsynced, err := st.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs: %v", err)
	}
	if len(unsynced) != 3 {
		t.Fatalf("want 3 unsynced audit rows, got %d", len(unsynced))
	}

	ids := make([]int64, len(unsynced))
	for i, row := range unsynced {
		ids[i] = row.ID
	}
	if err := st.MarkAuditLogSynced(ids); err != nil {
		t.Fatalf("MarkAuditLogSynced: %v", err)
	}

	remaining, err := st.GetUnsyncedAuditLogs(0)
	if err != nil {
		t.Fatalf("GetUnsyncedAuditLogs after sync: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("want 0 unsynced rows after marking synced, got %d", len(remaining))
	}
}

// TestEPMEndToEnd_PolicyResyncPrunesRemovedRules verifies that a second,
// smaller policy-sync delivery converges the local cache to exactly the new
// rule set — the same idempotent full-replace behavior FR-3.2 requires, now
// exercised through the complete handler -> store -> engine chain rather
// than the store alone.
func TestEPMEndToEnd_PolicyResyncPrunesRemovedRules(t *testing.T) {
	cfg := testEPMCfg(t)
	h := &epmPolicySyncHandler{}

	first := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-keep", "app_path": "/opt/tool", "decision": "allow"},
			{"id": "rule-drop", "app_path": "/opt/old-tool", "decision": "allow"},
		},
	}
	if _, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: first}); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	second := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-keep", "app_path": "/opt/tool", "decision": "allow"},
		},
	}
	if _, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: second}); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("open EPM store: %v", err)
	}
	defer func() { _ = st.Close() }()

	rules, err := st.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "rule-keep" {
		t.Fatalf("expected only rule-keep to remain after resync, got %+v", rules)
	}

	engine := epm.NewEngine(rules)
	dropped := engine.Evaluate(epm.ElevationRequest{AppPath: "/opt/old-tool"})
	if dropped.Allowed {
		t.Error("rule-drop was pruned; a request matching its old path must now be denied")
	}
}
