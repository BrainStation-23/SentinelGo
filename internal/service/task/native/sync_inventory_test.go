package native

// White-box tests for the sync-inventory handler.
// Using package native (not native_test) to access collectSysInfoFn and updateAgentInfoFn.

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/taskstore"
)

func testInvCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Path:        filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL: "https://test.supabase.co",
		AgentID:     "test-agent-id",
	}
}

func TestSyncInventoryHandler_Slugs(t *testing.T) {
	h := &syncInventoryHandler{}
	slugs := h.Slugs()
	found := false
	for _, s := range slugs {
		if s == "sync-inventory" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'sync-inventory': %v", slugs)
	}
}

func TestSyncInventoryHandler_CollectorReturnsNil_Error(t *testing.T) {
	origCollect := collectSysInfoFn
	origUpdate := updateAgentInfoFn
	defer func() {
		collectSysInfoFn = origCollect
		updateAgentInfoFn = origUpdate
	}()

	collectSysInfoFn = func(context.Context) (*shared.SystemInfo, error) { return nil, nil }
	updateAgentInfoFn = func(_ context.Context, _ *config.Config, _ *shared.SystemInfo) error {
		t.Error("UpdateAgentInfo should not be called when collect returns nil")
		return nil
	}

	h := &syncInventoryHandler{}
	_, err := h.Run(context.Background(), testInvCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when collector returns nil")
	}
}

func TestSyncInventoryHandler_UpdateAgentInfoFails_ReturnsError(t *testing.T) {
	origCollect := collectSysInfoFn
	origUpdate := updateAgentInfoFn
	defer func() {
		collectSysInfoFn = origCollect
		updateAgentInfoFn = origUpdate
	}()

	collectSysInfoFn = func(context.Context) (*shared.SystemInfo, error) { return &shared.SystemInfo{}, nil }

	updateErr := errors.New("supabase unavailable")
	updateAgentInfoFn = func(_ context.Context, _ *config.Config, _ *shared.SystemInfo) error {
		return updateErr
	}

	h := &syncInventoryHandler{}
	_, err := h.Run(context.Background(), testInvCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when UpdateAgentInfo fails")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("expected wrapped updateErr, got: %v", err)
	}
}

func TestSyncInventoryHandler_Success(t *testing.T) {
	origCollect := collectSysInfoFn
	origUpdate := updateAgentInfoFn
	defer func() {
		collectSysInfoFn = origCollect
		updateAgentInfoFn = origUpdate
	}()

	collectSysInfoFn = func(context.Context) (*shared.SystemInfo, error) {
		return &shared.SystemInfo{Hostname: "test-host"}, nil
	}
	updateAgentInfoFn = func(_ context.Context, _ *config.Config, _ *shared.SystemInfo) error { return nil }

	h := &syncInventoryHandler{}
	note, err := h.Run(context.Background(), testInvCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("expected no error on success, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty success note")
	}
}

func TestSyncInventoryHandler_Timeout(t *testing.T) {
	origCollect := collectSysInfoFn
	origUpdate := updateAgentInfoFn
	defer func() {
		collectSysInfoFn = origCollect
		updateAgentInfoFn = origUpdate
	}()

	// Use a pre-cancelled context to simulate a timeout without actually waiting 90s.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A collector that runs until its context ends, which is what a real one now
	// does: osinfo.CollectContext checks the deadline between collectors and the
	// security collector's subprocesses are killed outright. Previously this
	// stub could only block forever, because nothing was passed to it that could
	// ask it to stop — the handler abandoned the goroutine and returned, leaving
	// the collection and its subprocesses running.
	started := make(chan struct{})
	returned := make(chan struct{})
	collectSysInfoFn = func(ctx context.Context) (*shared.SystemInfo, error) {
		close(started)
		<-ctx.Done()
		close(returned)
		return nil, ctx.Err()
	}
	updateAgentInfoFn = func(_ context.Context, _ *config.Config, _ *shared.SystemInfo) error { return nil }

	h := &syncInventoryHandler{}
	_, err := h.Run(ctx, testInvCfg(t), taskstore.Task{})

	if err == nil {
		t.Fatal("expected error when context is cancelled before collection completes")
	}

	// The collector must have been given the cancellable context and must have
	// finished because of it. Both channels being closed by the time Run
	// returned is the proof that nothing was left running behind it.
	select {
	case <-started:
	default:
		t.Error("the collector was never invoked with the handler's context")
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Error("the collector did not observe cancellation; it was abandoned " +
			"rather than stopped, which is the leak this change removes")
	}
}

func TestSyncInventoryHandler_GoroutineDoesNotLeak(t *testing.T) {
	origCollect := collectSysInfoFn
	origUpdate := updateAgentInfoFn
	defer func() {
		collectSysInfoFn = origCollect
		updateAgentInfoFn = origUpdate
	}()

	// There is no goroutine to leak any more: the handler calls the collector
	// directly and the collector honours the context. This asserts the stronger
	// property the old buffered-channel arrangement could not — that collection
	// has actually finished by the time Run returns.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var running atomic.Bool
	collectSysInfoFn = func(ctx context.Context) (*shared.SystemInfo, error) {
		running.Store(true)
		defer running.Store(false)
		return nil, ctx.Err()
	}
	updateAgentInfoFn = func(_ context.Context, _ *config.Config, _ *shared.SystemInfo) error { return nil }

	h := &syncInventoryHandler{}
	h.Run(ctx, testInvCfg(t), taskstore.Task{}) //nolint:errcheck

	if running.Load() {
		t.Error("collection was still running after Run returned — the handler " +
			"stopped waiting for it rather than stopping it")
	}
}
