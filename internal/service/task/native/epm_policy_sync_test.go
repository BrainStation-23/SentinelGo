package native

// White-box tests for the epm-policy-sync handler.
// Using package native (not native_test) to access the test seams.

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func testEPMCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{Path: filepath.Join(dir, "config.json")}
}

func TestEPMPolicySyncHandler_Slugs(t *testing.T) {
	h := &epmPolicySyncHandler{}
	found := false
	for _, s := range h.Slugs() {
		if s == "epm-policy-sync" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'epm-policy-sync': %v", h.Slugs())
	}
}

func TestEPMPolicySyncHandler_UpsertsAndReportsCount(t *testing.T) {
	cfg := testEPMCfg(t)
	payload := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-1", "app_path": "/tool", "decision": "allow", "priority": float64(10)},
			{"id": "rule-2", "app_hash": "abc123", "decision": "deny", "priority": float64(20)},
		},
	}

	h := &epmPolicySyncHandler{}
	note, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: payload})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(note, "2 rules") {
		t.Errorf("note = %q, want it to mention 2 rules", note)
	}

	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("open store to verify: %v", err)
	}
	defer func() { _ = st.Close() }()

	rules, err := st.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 persisted rules, got %d", len(rules))
	}
}

func TestEPMPolicySyncHandler_PrunesRulesNotInPayload(t *testing.T) {
	cfg := testEPMCfg(t)
	h := &epmPolicySyncHandler{}

	firstPayload := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-1", "decision": "allow"},
			{"id": "rule-2", "decision": "allow"},
		},
	}
	if _, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: firstPayload}); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	secondPayload := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-1", "decision": "allow"},
		},
	}
	if _, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: secondPayload}); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("open store to verify: %v", err)
	}
	defer func() { _ = st.Close() }()

	rules, err := st.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "rule-1" {
		t.Fatalf("want only rule-1 to remain after resync, got %+v", rules)
	}
}

func TestEPMPolicySyncHandler_EmptyRulesWipesCache(t *testing.T) {
	cfg := testEPMCfg(t)
	h := &epmPolicySyncHandler{}

	if _, err := h.Run(context.Background(), cfg, taskstore.Task{
		Payload: map[string]interface{}{"rules": []map[string]interface{}{{"id": "rule-1", "decision": "allow"}}},
	}); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: map[string]interface{}{}}); err != nil {
		t.Fatalf("second Run (no rules): %v", err)
	}

	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("open store to verify: %v", err)
	}
	defer func() { _ = st.Close() }()

	rules, err := st.GetRules()
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("want 0 rules after empty-payload resync, got %d", len(rules))
	}
}

func TestEPMPolicySyncHandler_MalformedRulesReturnsError(t *testing.T) {
	cfg := testEPMCfg(t)
	h := &epmPolicySyncHandler{}

	payload := map[string]interface{}{
		"rules": []map[string]interface{}{
			{"id": "rule-1", "expires_at": "not-a-date"},
		},
	}
	_, err := h.Run(context.Background(), cfg, taskstore.Task{Payload: payload})
	if err == nil {
		t.Fatal("expected error for malformed expires_at")
	}
}

func TestEPMPolicySyncHandler_StoreOpenFailureReturnsError(t *testing.T) {
	orig := openEPMStoreFn
	t.Cleanup(func() { openEPMStoreFn = orig })
	openErr := errors.New("disk unavailable")
	openEPMStoreFn = func(_ *config.Config) (*store.EPMStore, error) { return nil, openErr }

	h := &epmPolicySyncHandler{}
	_, err := h.Run(context.Background(), testEPMCfg(t), taskstore.Task{Payload: map[string]interface{}{}})
	if err == nil || !errors.Is(err, openErr) {
		t.Fatalf("expected wrapped open error, got %v", err)
	}
}
