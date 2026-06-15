package native

// White-box tests for the firewall-enable handler.
// Using package native (not native_test) to access enableFirewallFn.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

func testFirewallCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        filepath.Join(dir, "config.json"),
		SupabaseURL: "https://test.supabase.co",
	}
}

func TestFirewallEnableHandler_Slugs(t *testing.T) {
	h := &firewallEnableHandler{}
	slugs := h.Slugs()
	found := false
	for _, s := range slugs {
		if s == "firewall-enable" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'firewall-enable': %v", slugs)
	}
}

func TestFirewallEnableHandler_PostRun(t *testing.T) {
	h := &firewallEnableHandler{}
	post := h.PostRun()
	found := false
	for _, s := range post {
		if s == "sync-inventory" {
			found = true
		}
	}
	if !found {
		t.Errorf("PostRun() does not contain 'sync-inventory': %v", post)
	}
}

func TestFirewallEnableHandler_LinuxNonRoot_ReturnsError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	h := &firewallEnableHandler{}
	_, err := h.Run(context.Background(), testFirewallCfg(t), taskstore.Task{ID: "priv-task"})
	if err == nil {
		t.Fatal("expected privilege error on Linux as non-root")
	}
}

func TestFirewallEnableHandler_DarwinNonRoot_ReturnsError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	h := &firewallEnableHandler{}
	_, err := h.Run(context.Background(), testFirewallCfg(t), taskstore.Task{ID: "priv-task"})
	if err == nil {
		t.Fatal("expected privilege error on macOS as non-root")
	}
}

func TestFirewallEnableHandler_Success_ReturnsNote(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Getuid() != 0 {
			t.Skip("skipping: non-root would fail privilege check before reaching firewall enable")
		}
	}

	orig := enableFirewallFn
	defer func() { enableFirewallFn = orig }()
	enableFirewallFn = func(_ context.Context) error { return nil }

	h := &firewallEnableHandler{}
	note, err := h.Run(context.Background(), testFirewallCfg(t), taskstore.Task{ID: "fw-ok"})
	if err != nil {
		t.Fatalf("expected no error on success, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty success note")
	}
}

func TestFirewallEnableHandler_CommandFailure_WrapsError(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Getuid() != 0 {
			t.Skip("skipping: non-root would fail privilege check before reaching firewall enable")
		}
	}

	orig := enableFirewallFn
	defer func() { enableFirewallFn = orig }()
	fwErr := errors.New("ufw: command not found")
	enableFirewallFn = func(_ context.Context) error { return fwErr }

	h := &firewallEnableHandler{}
	_, err := h.Run(context.Background(), testFirewallCfg(t), taskstore.Task{ID: "fw-fail"})
	if err == nil {
		t.Fatal("expected error when firewall command fails")
	}
	if !errors.Is(err, fwErr) {
		t.Errorf("expected wrapped fwErr, got: %v", err)
	}
}
