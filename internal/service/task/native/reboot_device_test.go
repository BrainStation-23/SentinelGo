package native

// White-box tests for the reboot-device handler.
// Using package native (not native_test) to access rebootFn.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/taskstore"
)

func testRebootCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        filepath.Join(dir, "config.json"),
		SupabaseURL: "https://test.supabase.co",
	}
}

func TestRebootDeviceHandler_Slugs(t *testing.T) {
	h := &rebootDeviceHandler{}
	slugs := h.Slugs()
	found := false
	for _, s := range slugs {
		if s == "device-reboot" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'device-reboot': %v", slugs)
	}
}

func TestRebootDeviceHandler_LinuxNonRoot_ReturnsError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	h := &rebootDeviceHandler{}
	cfg := testRebootCfg(t)

	_, err := h.Run(context.Background(), cfg, taskstore.Task{ID: "priv-task"})
	if err == nil {
		t.Fatal("expected privilege error on Linux as non-root")
	}

	// No restart context should be written when the privilege check fails.
	ctxPath := restartctx.PathFor(cfg.Path)
	if _, statErr := os.Stat(ctxPath); !os.IsNotExist(statErr) {
		t.Error("restart context must not be written when privilege check fails")
	}
}

func TestRebootDeviceHandler_RebootSuccess_WritesContextAndReturnsSuccess(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("skipping: Linux non-root would fail before reaching reboot")
	}

	orig := rebootFn
	defer func() { rebootFn = orig }()
	rebootFn = func() error { return nil }

	h := &rebootDeviceHandler{}
	cfg := testRebootCfg(t)
	task := taskstore.Task{ID: "reboot-ok"}

	note, err := h.Run(context.Background(), cfg, task)
	if err != nil {
		t.Fatalf("expected no error on successful reboot, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty success note")
	}

	// The restart context file should exist after a successful reboot call so
	// the agent can mark the task success after coming back up.
	ctxPath := restartctx.PathFor(cfg.Path)
	rc, err := restartctx.ReadAndClear(ctxPath)
	if err != nil {
		t.Fatalf("ReadAndClear: %v", err)
	}
	if rc == nil {
		t.Fatal("restart context should exist after successful reboot initiation")
	}
	if rc.TaskID != task.ID {
		t.Errorf("restart context TaskID: got %q, want %q", rc.TaskID, task.ID)
	}
	if rc.Reason != "device-reboot" {
		t.Errorf("restart context Reason: got %q, want %q", rc.Reason, "device-reboot")
	}
}

func TestRebootDeviceHandler_RebootFails_ClearsContext(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("skipping: Linux non-root would fail before reaching reboot")
	}

	orig := rebootFn
	defer func() { rebootFn = orig }()
	rebootErr := errors.New("shutdown: permission denied")
	rebootFn = func() error { return rebootErr }

	h := &rebootDeviceHandler{}
	cfg := testRebootCfg(t)

	_, err := h.Run(context.Background(), cfg, taskstore.Task{ID: "reboot-fail"})
	if err == nil {
		t.Fatal("expected error when reboot command fails")
	}

	// Restart context must be cleared so the next startup does not mark a
	// non-existent task as success.
	ctxPath := restartctx.PathFor(cfg.Path)
	if _, statErr := os.Stat(ctxPath); !os.IsNotExist(statErr) {
		t.Error("restart context should be cleared after reboot failure")
	}
}

func TestRebootDeviceHandler_RestartContextWrittenBeforeReboot(t *testing.T) {
	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		t.Skip("skipping: Linux non-root would fail before reaching reboot")
	}

	orig := rebootFn
	defer func() { rebootFn = orig }()

	var ctxExistedAtReboot bool
	rebootFn = func() error {
		// The restart context must already exist when reboot is triggered
		// so it survives the shutdown.
		return nil
	}

	h := &rebootDeviceHandler{}
	cfg := testRebootCfg(t)
	task := taskstore.Task{ID: "order-test"}

	// We intercept rebootFn and check the file exists at that moment.
	rebootFn = func() error {
		ctxPath := restartctx.PathFor(cfg.Path)
		_, err := os.Stat(ctxPath)
		ctxExistedAtReboot = err == nil
		return nil
	}

	_, _ = h.Run(context.Background(), cfg, task)
	if !ctxExistedAtReboot {
		t.Error("restart context must be written before the reboot command is issued")
	}
}
