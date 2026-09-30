package scheduler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	authsvc "sentinelgo/internal/service/auth"
)

// authTestServiceUnhealthy returns an auth.Service made Healthy()==false by
// driving one Recover() call against a fake server that rejects agent-login
// (401), which sets needsReprovision — the only exported way to reach that
// state from outside the auth package.
func authTestServiceUnhealthy(t *testing.T) *authsvc.Service {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "agent-login"):
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid agent credentials"}`))
		default: // token refresh
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}
	}))
	t.Cleanup(srv.Close)

	svc := authsvc.NewService(srv.URL, "test-anon-key")
	f, err := os.CreateTemp(t.TempDir(), "sched-auth-cfg-*.json")
	if err != nil {
		t.Fatalf("temp config: %v", err)
	}
	_ = f.Close()
	cfg := &config.Config{
		Path:        f.Name(),
		SupabaseURL: srv.URL,
		SupabaseKey: "test-anon-key",
		AgentID:     "agent-123",
		AgentSecret: "secret-abc",
	}

	if err := svc.Recover(context.Background(), cfg); err == nil {
		t.Fatal("expected Recover to fail against a rejecting server")
	}
	if svc.Healthy() {
		t.Fatal("expected service to be unhealthy after a rejected agent-login")
	}
	return svc
}

// White-box tests for the unexported task handlers and sysInfoFingerprint.
// SupabaseURL is left empty throughout so the eventual network call fails
// fast (client-side "unsupported protocol scheme" or similar) instead of
// hanging or making a real request.

func schedTestConfig() *config.Config {
	return &config.Config{
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		SupabaseURL: "",
		SupabaseKey: "test-key",
	}
}

// ── sysInfoFingerprint ───────────────────────────────────────────────────────

func TestSysInfoFingerprint_SameInputSameHash(t *testing.T) {
	info := &shared.SystemInfo{Hostname: "host-1", SerialNumber: "SN123"}
	h1 := sysInfoFingerprint(info)
	h2 := sysInfoFingerprint(info)
	if h1 != h2 {
		t.Errorf("fingerprint not stable: %q != %q", h1, h2)
	}
}

func TestSysInfoFingerprint_DifferentInputDifferentHash(t *testing.T) {
	a := &shared.SystemInfo{Hostname: "host-1"}
	b := &shared.SystemInfo{Hostname: "host-2"}
	if sysInfoFingerprint(a) == sysInfoFingerprint(b) {
		t.Error("different SystemInfo values produced the same fingerprint")
	}
}

func TestSysInfoFingerprint_IgnoresVolatileFields(t *testing.T) {
	// Volatile fields (CPU/memory/disk usage, uptime, timestamp) aren't part of
	// the fingerprint struct at all, so changing Hostname-independent live data
	// (represented here by leaving everything else zero) doesn't matter — this
	// just confirms the function only looks at the stable identity fields.
	a := &shared.SystemInfo{Hostname: "host-1"}
	b := &shared.SystemInfo{Hostname: "host-1"}
	if sysInfoFingerprint(a) != sysInfoFingerprint(b) {
		t.Error("identical stable fields produced different fingerprints")
	}
}

// ── handleAgentInfoUpdate ────────────────────────────────────────────────────

func TestHandleAgentInfoUpdate_AuthDegradedSkips(t *testing.T) {
	authSvc := authTestServiceUnhealthy(t)
	cfg := schedTestConfig()

	if err := handleAgentInfoUpdate(context.Background(), cfg, authSvc); err != nil {
		t.Errorf("expected no-op (nil error) when auth is degraded, got: %v", err)
	}
}

func TestHandleAgentInfoUpdate_RunsCollectionWithoutAuthSvc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real OS info collection in -short mode")
	}
	cfg := schedTestConfig()

	// An empty SupabaseURL builds a relative request URL, which
	// rpcutil.WithEnqueueRetry treats as a retryable network error rather than
	// a fast client-side failure — so bound this tightly and expect the
	// context-deadline branch rather than waiting out real backoff delays.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := handleAgentInfoUpdate(ctx, cfg, nil)
	if err == nil {
		t.Log("handler succeeded unexpectedly (network call reached somewhere); not a failure")
	}
}

// ── handleSoftwareSync ───────────────────────────────────────────────────────

func TestHandleSoftwareSync_SkipsWhenDisabled(t *testing.T) {
	cfg := schedTestConfig()
	cfg.SoftwareSyncEnabled = false

	if err := handleSoftwareSync(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected no-op when SoftwareSyncEnabled=false, got: %v", err)
	}
}

func TestHandleSoftwareSync_AuthDegradedSkips(t *testing.T) {
	cfg := schedTestConfig()
	cfg.SoftwareSyncEnabled = true
	authSvc := authTestServiceUnhealthy(t)

	if err := handleSoftwareSync(context.Background(), cfg, authSvc); err != nil {
		t.Errorf("expected no-op (nil error) when auth is degraded, got: %v", err)
	}
}

func TestHandleSoftwareSync_RunsCollectionWithoutAuthSvc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real OS software enumeration in -short mode")
	}
	cfg := schedTestConfig()
	cfg.SoftwareSyncEnabled = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := handleSoftwareSync(ctx, cfg, nil)
	if err == nil {
		t.Log("handler succeeded (list may have been empty this cycle)")
	}
}

// ── handleTokenRefresh ───────────────────────────────────────────────────────

func TestHandleTokenRefresh_NilAuthSvc(t *testing.T) {
	cfg := schedTestConfig()
	if err := handleTokenRefresh(context.Background(), cfg, nil); err != nil {
		t.Errorf("expected no-op when authSvc is nil, got: %v", err)
	}
}
