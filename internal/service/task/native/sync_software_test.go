package native

// White-box tests for the sync-software handler.
// Using package native (not native_test) to access sendSoftwareFn.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	swsvc "sentinelgo/internal/service/software"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

func testSwCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        filepath.Join(dir, "config.json"),
		SupabaseURL: "https://test.supabase.co",
		DeviceID:    "test-device",
		AccessToken: "test-token",
	}
}

func TestSyncSoftwareHandler_Slugs(t *testing.T) {
	h := &syncSoftwareHandler{}
	slugs := h.Slugs()
	found := false
	for _, s := range slugs {
		if s == "sync-software" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'sync-software': %v", slugs)
	}
}

func TestSyncSoftwareHandler_StoreFails_WhenDirAbsent(t *testing.T) {
	h := &syncSoftwareHandler{}
	// Point cfg.Path at a file inside a non-existent subdirectory so that
	// NewSoftwareStore fails to create the SQLite file.
	cfg := &config.Config{
		Path: filepath.Join(t.TempDir(), "nodir", "config.json"),
	}

	_, err := h.Run(context.Background(), cfg, taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when software store directory does not exist")
	}
}

func TestSyncSoftwareHandler_EmptyCatalog_ReturnsSuccess(t *testing.T) {
	origSend := sendSoftwareFn
	origList := getSoftwareListFn
	defer func() {
		sendSoftwareFn = origSend
		getSoftwareListFn = origList
	}()

	// Force an empty software list so the catalog path is empty.
	getSoftwareListFn = func(_ *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, map[string]bool) { return nil, nil }
	sendSoftwareFn = func(_ context.Context, _ *swsvc.SoftwareService, _ string, _ []swsvc.SoftwareInfo, _ *config.Config) error {
		return errors.New("SendByRPC must not be called for empty catalog")
	}

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("expected no error for empty catalog, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty note for empty catalog")
	}
}

func TestSyncSoftwareHandler_SendFails_ReturnsError(t *testing.T) {
	origSend := sendSoftwareFn
	origList := getSoftwareListFn
	defer func() {
		sendSoftwareFn = origSend
		getSoftwareListFn = origList
	}()

	// Return one fake package so the catalog is non-empty and SendByRPC is reached.
	getSoftwareListFn = func(_ *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, map[string]bool) {
		return []swsvc.SoftwareInfo{{Name: "fake-pkg", Source: "programs", InstalledVersion: "1.0"}}, map[string]bool{"programs": true}
	}

	sendErr := errors.New("RPC unavailable")
	sendSoftwareFn = func(_ context.Context, _ *swsvc.SoftwareService, _ string, _ []swsvc.SoftwareInfo, _ *config.Config) error {
		return sendErr
	}

	h := &syncSoftwareHandler{}
	_, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when SendByRPC fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}
