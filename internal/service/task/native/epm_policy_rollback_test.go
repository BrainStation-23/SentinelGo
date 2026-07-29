package native

// White-box tests for the epm-policy-rollback handler.
// Using package native (not native_test) to access the test seams.

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func openRollbackTestStore(t *testing.T, cfg *config.Config) *store.EPMStore {
	t.Helper()
	st, err := store.NewEPMStore(filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName))
	if err != nil {
		t.Fatalf("NewEPMStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestEPMPolicyRollbackHandler_Slugs(t *testing.T) {
	h := &epmPolicyRollbackHandler{}
	found := false
	for _, s := range h.Slugs() {
		if s == "epm-policy-rollback" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'epm-policy-rollback': %v", h.Slugs())
	}
}

func TestEPMPolicyRollbackHandler_MissingGeneration(t *testing.T) {
	h := &epmPolicyRollbackHandler{}
	_, err := h.Run(context.Background(), testEPMCfg(t), taskstore.Task{Payload: map[string]interface{}{}})
	if err == nil {
		t.Fatal("expected an error for a payload with no \"generation\" key")
	}
}

func TestEPMPolicyRollbackHandler_UnknownGeneration(t *testing.T) {
	cfg := testEPMCfg(t)
	h := &epmPolicyRollbackHandler{}
	_, err := h.Run(context.Background(), cfg, taskstore.Task{
		Payload: map[string]interface{}{"generation": float64(999)},
	})
	if err == nil {
		t.Fatal("expected an error rolling back to a generation that does not exist")
	}
}

func TestEPMPolicyRollbackHandler_RollsBackToPreviousGeneration(t *testing.T) {
	cfg := testEPMCfg(t)
	st := openRollbackTestStore(t, cfg)

	now := time.Now().UTC()
	if err := st.InsertBundle(store.BundleRow{
		BundleID: "gen-1", Generation: 1, Mode: "full",
		IssuedAt: now, ReceivedAt: now, State: store.BundleStateSuperseded, Payload: []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed generation 1: %v", err)
	}
	if err := st.InsertBundle(store.BundleRow{
		BundleID: "gen-2", Generation: 2, Mode: "full",
		IssuedAt: now, ReceivedAt: now, State: store.BundleStateActive, Payload: []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed generation 2: %v", err)
	}

	h := &epmPolicyRollbackHandler{}
	note, err := h.Run(context.Background(), cfg, taskstore.Task{
		Payload: map[string]interface{}{"generation": float64(1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(note, "gen-1") {
		t.Errorf("note = %q, want it to mention gen-1", note)
	}

	active, err := st.ActiveBundle()
	if err != nil {
		t.Fatalf("ActiveBundle: %v", err)
	}
	if active == nil || active.BundleID != "gen-1" {
		t.Fatalf("active bundle = %+v, want gen-1", active)
	}

	old, err := st.GetBundle("gen-2")
	if err != nil {
		t.Fatalf("GetBundle(gen-2): %v", err)
	}
	if old == nil || old.State != store.BundleStateSuperseded {
		t.Errorf("gen-2 state = %+v, want superseded (ActivateBundle's atomic supersede)", old)
	}
}

func TestEPMPolicyRollbackHandler_AlreadyActiveIsNoop(t *testing.T) {
	cfg := testEPMCfg(t)
	st := openRollbackTestStore(t, cfg)

	now := time.Now().UTC()
	if err := st.InsertBundle(store.BundleRow{
		BundleID: "gen-1", Generation: 1, Mode: "full",
		IssuedAt: now, ReceivedAt: now, State: store.BundleStateActive, Payload: []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := &epmPolicyRollbackHandler{}
	note, err := h.Run(context.Background(), cfg, taskstore.Task{
		Payload: map[string]interface{}{"generation": float64(1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(note, "already active") {
		t.Errorf("note = %q, want it to mention already active", note)
	}
}

func TestEPMPolicyRollbackHandler_StoreOpenFailureReturnsError(t *testing.T) {
	orig := openEPMStoreFn
	t.Cleanup(func() { openEPMStoreFn = orig })
	openErr := errors.New("disk unavailable")
	openEPMStoreFn = func(_ *config.Config) (*store.EPMStore, error) { return nil, openErr }

	h := &epmPolicyRollbackHandler{}
	_, err := h.Run(context.Background(), testEPMCfg(t), taskstore.Task{
		Payload: map[string]interface{}{"generation": float64(1)},
	})
	if err == nil || !errors.Is(err, openErr) {
		t.Fatalf("expected wrapped open error, got %v", err)
	}
}
