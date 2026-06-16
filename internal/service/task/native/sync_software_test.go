package native

// White-box tests for the sync-software handler.
// Using package native (not native_test) to access the test seams.

import (
	"context"
	"errors"
	"strings"
	"testing"

	swsvc "sentinelgo/internal/service/software"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

func testSwCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        dir + "/config.json",
		SupabaseURL: "https://test.supabase.co",
		DeviceID:    "test-device",
		AccessToken: "test-token",
	}
}

// stubSoftware swaps the handler's collect/sync seams for the duration of a test.
func stubSoftware(t *testing.T, list []swsvc.SoftwareInfo, complete bool, sync func(context.Context, *swsvc.SoftwareService, *config.Config, []swsvc.SoftwareInfo, bool) (bool, error)) {
	t.Helper()
	origList := getSoftwareListFn
	origSync := syncSoftwareFn
	t.Cleanup(func() {
		getSoftwareListFn = origList
		syncSoftwareFn = origSync
	})
	getSoftwareListFn = func(_ *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, bool) { return list, complete }
	syncSoftwareFn = sync
}

func TestSyncSoftwareHandler_Slugs(t *testing.T) {
	h := &syncSoftwareHandler{}
	found := false
	for _, s := range h.Slugs() {
		if s == "sync-software" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'sync-software': %v", h.Slugs())
	}
}

func TestSyncSoftwareHandler_EmptyCatalog_ReturnsSuccess(t *testing.T) {
	stubSoftware(t, nil, true, func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
		return false, errors.New("sync must not be called for empty list")
	})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("expected no error for empty list, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty note for empty list")
	}
}

func TestSyncSoftwareHandler_SendFails_ReturnsError(t *testing.T) {
	sendErr := errors.New("RPC unavailable")
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "fake-pkg", Source: "programs", InstalledVersion: "1.0"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return false, sendErr
		})

	h := &syncSoftwareHandler{}
	_, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when send fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

func TestSyncSoftwareHandler_Sent_ReportsCount(t *testing.T) {
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return false, nil // sent (not skipped)
		})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(note, "synced successfully") || !strings.Contains(note, "3 items") {
		t.Errorf("note = %q, want 'synced successfully: 3 items'", note)
	}
}

func TestSyncSoftwareHandler_Skipped_ReportsUnchanged(t *testing.T) {
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "a"}, {Name: "b"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return true, nil // skipped (deduped)
		})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(note, "unchanged") {
		t.Errorf("note = %q, want it to report 'unchanged'", note)
	}
}
