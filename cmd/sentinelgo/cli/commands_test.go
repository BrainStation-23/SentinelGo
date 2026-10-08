package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
	swsvc "sentinelgo/internal/service/software"
)

// captureStdout redirects os.Stdout for the duration of fn, returns printed text.
// The pipe is drained concurrently while fn runs (not just after it returns) so
// output larger than the OS pipe buffer doesn't deadlock fn's write call.
func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = old

	return <-done
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
			FirstSeenAt:      now,
		},
		{
			Name:             "chrome-ext",
			Type:             "chrome_extensions",
			Source:           "chrome_extensions",
			InstalledVersion: "1.0",
			DisplayName:      "Chrome Extension",
			FilePath:         "/path/to/ext",
			FirstSeenAt:      now,
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
			FirstSeenAt:      now,
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
		{Name: "curl", Source: "deb_packages", FirstSeenAt: now},
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

// ── withLoggingIntegrationForConfig ──────────────────────────────────────────

func TestWithLoggingIntegrationForConfig_ActionCalled(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             filepath.Join(t.TempDir(), "config.json"),
	}
	var called bool
	err := withLoggingIntegrationForConfig(cfg, func(_ *logging.LoggingIntegration, _ context.Context) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !called {
		t.Error("action was not called")
	}
}

func TestWithLoggingIntegrationForConfig_ActionError(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             filepath.Join(t.TempDir(), "config.json"),
	}
	boom := fmt.Errorf("boom")
	err := withLoggingIntegrationForConfig(cfg, func(_ *logging.LoggingIntegration, _ context.Context) error {
		return boom
	})
	if err == nil {
		t.Error("expected error from action, got nil")
	}
}

// ── HandleEnableAutoUpdate ────────────────────────────────────────────────────

func TestHandleEnableAutoUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	testCfg := `{
		"supabase_url": "https://example.supabase.co",
		"supabase_key": "test-anon-key",
		"device_id":    "test-device-id",
		"auto_update":  false
	}`
	if err := os.WriteFile(cfgPath, []byte(testCfg), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	HandleEnableAutoUpdate(cfgPath)

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load after HandleEnableAutoUpdate: %v", err)
	}
	if !saved.AutoUpdate {
		t.Error("expected AutoUpdate=true after HandleEnableAutoUpdate")
	}
}

// ── HandleAgentInfoUpdate ─────────────────────────────────────────────────────

func TestHandleAgentInfoUpdate_NoTokens(t *testing.T) {
	cfg := &config.Config{
		SupabaseURL:  "https://test.supabase.co",
		DeviceID:     "test-device",
		AccessToken:  "",
		RefreshToken: "",
	}
	out := captureStdout(func() { HandleAgentInfoUpdate(cfg) })
	if !strings.Contains(out, "No tokens") {
		t.Errorf("expected No tokens message; got: %q", out)
	}
}

// TestHandleAgentInfoUpdate_NeverRefreshes: when the stored token is rejected,
// the CLI must not refresh (a refresh from a second process would revoke the
// running service's token family). It logs in for this command only and never
// writes the config.
func TestHandleAgentInfoUpdate_NeverRefreshes(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/functions/v1/agent-login" {
			_, _ = w.Write([]byte(`{"access_token":"cli-token","refresh_token":"cli-refresh","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"PGRST301","message":"JWT expired"}`))
	}))
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := &config.Config{
		Path:         cfgPath,
		SupabaseURL:  srv.URL,
		DeviceID:     "test-device",
		AgentID:      "agent-1",
		AgentSecret:  "secret",
		AccessToken:  "stored-token",
		RefreshToken: "test-refresh-token",
		SupabaseKey:  "test-key",
	}
	out := captureStdout(func() { HandleAgentInfoUpdate(cfg) })
	if !strings.Contains(out, "Logging in for this command only") {
		t.Errorf("expected an in-memory login; got: %q", out)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(p, "/auth/v1/") {
			t.Errorf("CLI made a token-refresh request to %s", p)
		}
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("CLI wrote the config file (stat err = %v)", err)
	}
	if cfg.GetRefreshToken() != "cli-refresh" {
		t.Errorf("in-memory refresh token = %q, want the agent-login one", cfg.GetRefreshToken())
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
