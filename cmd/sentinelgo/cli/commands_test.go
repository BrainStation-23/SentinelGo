package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	swsvc "sentinelgo/internal/service/software"
)

// captureStdout redirects os.Stdout for the duration of fn, returns printed text.
func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// ── HandleAuditLogsStatus ────────────────────────────────────────────────────

func TestHandleAuditLogsStatus_disabled(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "device-abc",
		CurrentVersion:   "v1.0.0",
		AuditLogsEnabled: false,
	}

	out := captureStdout(func() { HandleAuditLogsStatus(cfg) })

	if !strings.Contains(out, "device-abc") {
		t.Errorf("output missing DeviceID; got %q", out)
	}
	if !strings.Contains(out, "disabled") {
		t.Errorf("output should mention disabled; got %q", out)
	}
}

func TestHandleAuditLogsStatus_enabled(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "device-xyz",
		CurrentVersion:   "v2.0.0",
		AuditLogsEnabled: true,
	}

	out := captureStdout(func() { HandleAuditLogsStatus(cfg) })

	if !strings.Contains(out, "configured to run") {
		t.Errorf("output should mention configured to run; got %q", out)
	}
}

// ── showSoftwareList ─────────────────────────────────────────────────────────

func TestShowSoftwareList_empty(t *testing.T) {
	out := captureStdout(func() { showSoftwareList(nil) })
	if !strings.Contains(out, "0") {
		t.Errorf("expected 0 in output for empty list, got %q", out)
	}
}

func TestShowSoftwareList_items(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	list := []swsvc.SoftwareInfo{
		{
			Name:             "curl",
			Type:             "deb_packages",
			Source:           "deb_packages",
			InstalledVersion: "7.88.1",
			DisplayName:      "",
			FilePath:         "",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		},
		{
			Name:             "chrome-ext",
			Type:             "chrome_extensions",
			Source:           "chrome_extensions",
			InstalledVersion: "1.0",
			DisplayName:      "Chrome Extension",
			FilePath:         "/path/to/ext",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		},
	}

	out := captureStdout(func() { showSoftwareList(list) })

	if !strings.Contains(out, "curl") {
		t.Errorf("output missing 'curl'; got %q", out)
	}
	if !strings.Contains(out, "chrome_extensions") {
		t.Errorf("output missing 'chrome_extensions'; got %q", out)
	}
}

func TestShowSoftwareList_displayNameAndPath(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	list := []swsvc.SoftwareInfo{
		{
			Name:             "my-app",
			Type:             "applications",
			Source:           "applications",
			InstalledVersion: "3.0",
			DisplayName:      "My Application",
			FilePath:         "/Applications/MyApp.app",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		},
	}

	out := captureStdout(func() { showSoftwareList(list) })

	if !strings.Contains(out, "My Application") {
		t.Errorf("output missing DisplayName; got %q", out)
	}
	if !strings.Contains(out, "/Applications/MyApp.app") {
		t.Errorf("output missing FilePath; got %q", out)
	}
}

// ── outputSoftwareJSON ───────────────────────────────────────────────────────

func TestOutputSoftwareJSON(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	list := []swsvc.SoftwareInfo{
		{Name: "curl", Source: "deb_packages", FirstSeenAt: now, LastSeenAt: now, IsActive: true},
	}

	out := captureStdout(func() { outputSoftwareJSON(list) })

	var decoded []swsvc.SoftwareInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("outputSoftwareJSON produced invalid JSON: %v\nOutput: %q", err, out)
	}
	if len(decoded) != 1 || decoded[0].Name != "curl" {
		t.Errorf("unexpected JSON content: %v", decoded)
	}
}

func TestOutputSoftwareJSON_empty(t *testing.T) {
	out := captureStdout(func() { outputSoftwareJSON(nil) })
	trimmed := strings.TrimSpace(out)
	if trimmed != "null" && trimmed != "[]" {
		t.Errorf("empty list should produce null or []; got %q", out)
	}
}

// ── getCheckpointPath ────────────────────────────────────────────────────────

func TestGetCheckpointPath(t *testing.T) {
	p := getCheckpointPath()
	if p == "" {
		t.Error("getCheckpointPath() returned empty string")
	}
}

// ── showSentinelGoStatus ─────────────────────────────────────────────────────

func TestShowSentinelGoStatus_noPanic(t *testing.T) {
	// showSentinelGoStatus calls procinfo.FindProcesses(). It may or may not find
	// processes; we only assert it doesn't panic and returns without error in the
	// common case (even if no processes are running).
	out := captureStdout(func() {
		err := showSentinelGoStatus()
		if err != nil {
			// non-fatal: some environments restrict process listing
			fmt.Fprintf(os.Stderr, "showSentinelGoStatus returned error (expected on some systems): %v\n", err)
		}
	})
	_ = out // output is environment-dependent; just assert no panic
}
