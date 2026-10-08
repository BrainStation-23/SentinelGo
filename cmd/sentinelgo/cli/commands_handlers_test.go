package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/osinfo/shared"
)

// ── seam helpers ─────────────────────────────────────────────────────────────

// recordExit replaces osExit with a recorder so a handler's exit path returns
// instead of terminating the test binary. It returns the recorded codes.
func recordExit(t *testing.T) *[]int {
	t.Helper()
	var codes []int
	old := osExit
	t.Cleanup(func() { osExit = old })
	osExit = func(code int) { codes = append(codes, code) }
	return &codes
}

// recordFatal replaces logFatalf with a recorder (log.Fatalf would os.Exit).
func recordFatal(t *testing.T) *[]string {
	t.Helper()
	var msgs []string
	old := logFatalf
	t.Cleanup(func() { logFatalf = old })
	logFatalf = func(format string, v ...any) { msgs = append(msgs, fmt.Sprintf(format, v...)) }
	return &msgs
}

// stubOSInfo replaces the real (slow, host-dependent) OS info collector.
func stubOSInfo(t *testing.T) {
	t.Helper()
	old := collectOSInfo
	t.Cleanup(func() { collectOSInfo = old })
	collectOSInfo = func() *shared.SystemInfo { return &shared.SystemInfo{Hostname: "test-host"} }
}

// tempLoggingConfig is a config whose checkpoint dir and SQLite queue live in
// t.TempDir(), with no Supabase URL so nothing is ever uploaded.
func tempLoggingConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:         "test-device",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             filepath.Join(t.TempDir(), "config.json"),
	}
}

// unusableLoggingConfig points the checkpoint dir beneath a regular file, so
// logging.NewLoggingIntegration fails to create it.
func unusableLoggingConfig(t *testing.T) *config.Config {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return &config.Config{
		DeviceID: "test-device",
		Path:     filepath.Join(blocker, "sub", "config.json"),
	}
}

func wantExit(t *testing.T, codes *[]int, want ...int) {
	t.Helper()
	if fmt.Sprint(*codes) != fmt.Sprint(want) {
		t.Errorf("exit codes = %v, want %v", *codes, want)
	}
}

// ── HandleAuditLogsStandalone ────────────────────────────────────────────────

func TestHandleAuditLogsStandalone_StopsOnSignal(t *testing.T) {
	codes := recordExit(t)
	old := notifySignals
	t.Cleanup(func() { notifySignals = old })
	notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { c <- os.Interrupt }

	out := captureStdout(func() { HandleAuditLogsStandalone(tempLoggingConfig(t)) })

	wantExit(t, codes)
	for _, s := range []string{"standalone mode", "is running", "Stopping audit logs service"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q; got %q", s, out)
		}
	}
}

func TestHandleAuditLogsStandalone_IntegrationErrorExits(t *testing.T) {
	codes := recordExit(t)

	out := captureStdout(func() { HandleAuditLogsStandalone(nil) })

	wantExit(t, codes, 1)
	if !strings.Contains(out, "Failed to create logging integration") {
		t.Errorf("missing failure message; got %q", out)
	}
}

// ── withLoggingIntegration ───────────────────────────────────────────────────

func TestWithLoggingIntegrationForConfig_NewIntegrationError(t *testing.T) {
	called := false
	err := withLoggingIntegrationForConfig(unusableLoggingConfig(t), func(_ *logging.LoggingIntegration, _ context.Context) error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "failed to create logging integration") {
		t.Errorf("err = %v, want a create failure", err)
	}
	if called {
		t.Error("action ran despite the setup failure")
	}
}

func TestWithLoggingIntegration_ConfigLoadErrorExits(t *testing.T) {
	codes := recordExit(t)
	stubDefaultConfig(t, nil, errors.New("bad json"))

	out := captureStdout(HandleCollectLogs)

	wantExit(t, codes, 1)
	if strings.Contains(out, "Log collection completed") {
		t.Error("collection ran despite the config failure")
	}
	if !strings.Contains(out, "Failed to load config: bad json") {
		t.Errorf("missing config failure message; got %q", out)
	}
}

func TestWithLoggingIntegration_SetupErrorExits(t *testing.T) {
	codes := recordExit(t)
	stubDefaultConfig(t, unusableLoggingConfig(t), nil)

	out := captureStdout(HandleLoggingStats)

	wantExit(t, codes, 1)
	if !strings.Contains(out, "Error: failed to create logging integration") {
		t.Errorf("missing setup failure message; got %q", out)
	}
	if strings.Contains(out, "Logging Statistics") {
		t.Error("stats printed despite the setup failure")
	}
}

// ── HandleUploadLogs / HandleLoggingStats ────────────────────────────────────

// With an empty queue and no Supabase URL there is nothing to send, so the
// upload succeeds without any network traffic.
func TestHandleUploadLogs_EmptyQueue(t *testing.T) {
	codes := recordExit(t)
	stubDefaultConfig(t, tempLoggingConfig(t), nil)

	out := captureStdout(HandleUploadLogs)

	wantExit(t, codes)
	if !strings.Contains(out, "Uploading pending logs") {
		t.Errorf("missing banner; got %q", out)
	}
	if strings.Contains(out, "Upload failed") {
		t.Errorf("empty queue should not fail; got %q", out)
	}
}

func TestHandleLoggingStats(t *testing.T) {
	codes := recordExit(t)
	stubDefaultConfig(t, tempLoggingConfig(t), nil)

	out := captureStdout(HandleLoggingStats)

	wantExit(t, codes)
	for _, s := range []string{"Logging Statistics", "Logs Collected: 0", "Logs Stored: 0", "Logs Uploaded: 0", "Upload Errors: 0"} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q; got %q", s, out)
		}
	}
}

// ── HandleEnableAutoUpdate error paths ───────────────────────────────────────

func TestHandleEnableAutoUpdate_LoadErrorIsFatal(t *testing.T) {
	msgs := recordFatal(t)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte("{not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(func() { HandleEnableAutoUpdate(cfgPath) })

	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "Failed to load config") {
		t.Errorf("fatal messages = %q", *msgs)
	}
	if strings.Contains(out, "Auto-update enabled") {
		t.Error("reported success after a load failure")
	}
}

// A config missing required fields fails validation on save; the file on disk
// must be left as it was.
func TestHandleEnableAutoUpdate_SaveErrorIsFatal(t *testing.T) {
	msgs := recordFatal(t)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	orig := []byte(`{"device_id": "d", "auto_update": false}`)
	if err := os.WriteFile(cfgPath, orig, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(func() { HandleEnableAutoUpdate(cfgPath) })

	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "Failed to save config") {
		t.Errorf("fatal messages = %q", *msgs)
	}
	if strings.Contains(out, "Auto-update enabled") {
		t.Error("reported success after a save failure")
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != string(orig) {
		t.Errorf("config file changed: %s", got)
	}
}

// ── HandleAgentInfoUpdate: remaining branches ────────────────────────────────

// agentInfoServer answers agent-login with loginStatus and every other path
// (the inventory RPC) with rpcStatus.
func agentInfoServer(t *testing.T, loginStatus, rpcStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/functions/v1/agent-login" {
			w.WriteHeader(loginStatus)
			if loginStatus == http.StatusOK {
				_, _ = w.Write([]byte(`{"access_token":"cli-token","refresh_token":"cli-refresh","expires_in":3600}`))
			} else {
				_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
			}
			return
		}
		w.WriteHeader(rpcStatus)
		if rpcStatus >= 400 {
			_, _ = w.Write([]byte(`{"message":"boom"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func agentInfoConfig(t *testing.T, url, accessToken string) *config.Config {
	return &config.Config{
		Path:        filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL: url,
		SupabaseKey: "test-key",
		DeviceID:    "test-device",
		AgentID:     "agent-1",
		AgentSecret: "secret",
		AccessToken: accessToken,
	}
}

func TestHandleAgentInfoUpdate_StoredTokenSucceeds(t *testing.T) {
	stubOSInfo(t)
	srv := agentInfoServer(t, http.StatusInternalServerError, http.StatusOK)

	out := captureStdout(func() { HandleAgentInfoUpdate(agentInfoConfig(t, srv.URL, "stored-token")) })

	if !strings.Contains(out, "Agent information updated successfully") {
		t.Errorf("expected success; got %q", out)
	}
	if strings.Contains(out, "Logging in") {
		t.Errorf("a valid stored token must not trigger a login; got %q", out)
	}
}

func TestHandleAgentInfoUpdate_LoginFails(t *testing.T) {
	stubOSInfo(t)
	srv := agentInfoServer(t, http.StatusUnauthorized, http.StatusOK)

	out := captureStdout(func() { HandleAgentInfoUpdate(agentInfoConfig(t, srv.URL, "")) })

	if !strings.Contains(out, "Agent login failed") {
		t.Errorf("expected login failure; got %q", out)
	}
	if strings.Contains(out, "updated successfully") {
		t.Errorf("reported success after a failed login; got %q", out)
	}
}

func TestHandleAgentInfoUpdate_UpdateFailsAfterLogin(t *testing.T) {
	stubOSInfo(t)
	// 401 is returned without retry (a 5xx would back off until the 30s budget
	// runs out; any other 4xx is dropped as a poison payload and reported as success).
	srv := agentInfoServer(t, http.StatusOK, http.StatusUnauthorized)

	out := captureStdout(func() { HandleAgentInfoUpdate(agentInfoConfig(t, srv.URL, "")) })

	if !strings.Contains(out, "Logging in for this command only") {
		t.Errorf("expected an in-memory login; got %q", out)
	}
	if !strings.Contains(out, "Agent info update failed") {
		t.Errorf("expected update failure; got %q", out)
	}
}
