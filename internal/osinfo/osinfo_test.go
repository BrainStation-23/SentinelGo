package osinfo_test

import (
	"runtime"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/system"
)

func TestGetConfigDir(t *testing.T) {
	dir := system.GetConfigDir()
	if dir == "" {
		t.Error("GetConfigDir() returned empty string")
	}

	// Verify it returns platform-specific paths
	switch runtime.GOOS {
	case "windows":
		if dir != `C:\SentinelGo\.sentinelgo` {
			t.Errorf("GetConfigDir() on Windows should return 'C:\\SentinelGo\\.sentinelgo', got: %s", dir)
		}
	case "linux", "darwin":
		if dir != `/opt/sentinelgo/.sentinelgo` {
			t.Errorf("GetConfigDir() on Unix should return '/opt/sentinelgo/.sentinelgo', got: %s", dir)
		}
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
