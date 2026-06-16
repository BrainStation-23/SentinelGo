package native

// White-box tests for the sync-software handler.
// Using package native (not native_test) to access sendSoftwareFn.

import (
	"context"
	"errors"
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

func TestSyncSoftwareHandler_EmptyCatalog_ReturnsSuccess(t *testing.T) {
	origSend := sendSoftwareFn
	origList := getSoftwareListFn
	defer func() {
		sendSoftwareFn = origSend
		getSoftwareListFn = origList
	}()

	getSoftwareListFn = func(_ *swsvc.SoftwareService) []swsvc.SoftwareInfo { return nil }
	sendSoftwareFn = func(_ context.Context, _ *swsvc.SoftwareService, _ string, _ []swsvc.SoftwareInfo, _ *config.Config) error {
		return errors.New("SendByRPC must not be called for empty list")
	}

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
	origSend := sendSoftwareFn
	origList := getSoftwareListFn
	defer func() {
		sendSoftwareFn = origSend
		getSoftwareListFn = origList
	}()

	getSoftwareListFn = func(_ *swsvc.SoftwareService) []swsvc.SoftwareInfo {
		return []swsvc.SoftwareInfo{{Name: "fake-pkg", Source: "programs", InstalledVersion: "1.0"}}
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
