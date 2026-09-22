package osinfo_test

import (
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/system"
	"sentinelgo/internal/paths"
)

func TestGetConfigDir(t *testing.T) {
	dir := system.GetConfigDir()
	if dir == "" {
		t.Error("GetConfigDir() returned empty string")
	}

	// GetConfigDir must agree with internal/paths rather than carry its own copy
	// of the layout. It used to hardcode the platform paths itself, so the task
	// database could be created in a different directory from the config file it
	// was meant to sit beside -- and on Windows it named the location whose
	// inherited ACL left the install directory writable by any standard user.
	if want := paths.DataDir(); dir != want {
		t.Errorf("GetConfigDir() = %q, want %q (must match internal/paths)", dir, want)
	}
}

func TestGetOSQueryVersion(t *testing.T) {
	version := system.GetOSQueryVersion()
	if version == "" {
		t.Error("GetOSQueryVersion() returned empty string")
	}
	// It should return either a version number or "not installed"
	if version != "not installed" {
		// If it returns a version, it should contain a dot (e.g., "5.8.2")
		// This is a basic validation
		if !strings.Contains(version, ".") {
			t.Logf("Version %q does not contain a dot, but may still be valid", version)
		}
	}
}

func TestCollect(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	// Verify basic fields are populated
	if info.Hostname == "" {
		t.Error("Collect() should set Hostname")
	}

	if info.Timestamp.IsZero() {
		t.Error("Collect() should set Timestamp")
	}

	// CPU info should be present
	if info.CPU.ModelName == "" {
		t.Error("Collect() should set CPU ModelName")
	}

	if info.CPU.Cores == 0 {
		t.Error("Collect() should set CPU Cores")
	}

	// Memory info should be present
	if info.Memory.Total == 0 {
		t.Error("Collect() should set Memory Total")
	}

	// Disk info should be present
	if info.Disk.Total == 0 {
		t.Error("Collect() should set Disk Total")
	}

	// OS Information should be present
	if info.OSInformation.OSName == "" {
		t.Error("Collect() should set OS Name")
	}
}
