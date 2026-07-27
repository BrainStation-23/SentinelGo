package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/auth"
)

// Fake tokens. SetSession only places the access token into a header and
// InitSession only requires it to be non-empty; no JWT validation occurs
// client-side, so opaque placeholders are sufficient for these tests.
const (
	validAccessToken  = "fake-access-token"
	validRefreshToken = "fake-refresh-token"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestService() *auth.Service {
	return auth.NewService("https://test.supabase.co", "")
}

func newTestConfig(t *testing.T, accessToken, refreshToken string) *config.Config {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "sentinelgo-test-config-*.json")
	if err != nil {
		t.Fatalf("create temp config file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp config file: %v", err)
	}
	return &config.Config{
		Path:         f.Name(),
		SupabaseURL:  "https://test.supabase.co",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		DeviceID:     "09ef2eaf-ed10-431a-b4b4-f5e0f4b36829",
	}
}

// ── NewService ────────────────────────────────────────────────────────────────

func TestNewService(t *testing.T) {
	svc := auth.NewService("https://test.supabase.co", "")
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
}

func TestNewService_EmptyURL(t *testing.T) {
	svc := auth.NewService("", "")
	if svc == nil {
		t.Fatal("NewService() should handle empty URL")
	}
}

func TestNewService_InvalidURL(t *testing.T) {
	svc := auth.NewService("http://invalid-url", "")
	if svc == nil {
		t.Fatal("NewService() should handle invalid URL")
	}
}

// ── InitSession ───────────────────────────────────────────────────────────────

func TestInitSession_EmptyToken(t *testing.T) {
	svc := newTestService()
	cfg := newTestConfig(t, "", "")

	err := svc.InitSession(cfg)
	if err == nil {
		t.Fatal("expected error for empty access token, got nil")
	}
	if !strings.Contains(err.Error(), "no access token") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("✅ InitSession correctly rejected empty token: %v", err)
}

func TestInitSession_WithToken(t *testing.T) {
	svc := newTestService()
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)

	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed with valid token: %v", err)
	}
	t.Log("✅ InitSession succeeded with stored token")
}

// ── SetSession ────────────────────────────────────────────────────────────────

func TestSetSession_EmptyBaseURL(t *testing.T) {
	svc := auth.NewService("", "") // intentionally empty

	err := svc.SetSession(validAccessToken, "")
	if err == nil {
		t.Fatal("expected error for empty base URL, got nil")
	}
	if !strings.Contains(err.Error(), "base URL not configured") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("✅ SetSession correctly rejected empty base URL: %v", err)
}

func TestSetSession_ValidToken(t *testing.T) {
	svc := newTestService()

	if err := svc.SetSession(validAccessToken, validRefreshToken); err != nil {
		t.Fatalf("SetSession failed: %v", err)
	}
	t.Log("✅ SetSession succeeded")
}

func TestSetSession_AfterInitSession(t *testing.T) {
	svc := newTestService()
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)

	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	if err := svc.SetSession(validAccessToken, "updated-refresh-token"); err != nil {
		t.Fatalf("SetSession after InitSession failed: %v", err)
	}
	t.Log("✅ InitSession → SetSession sequence succeeded")
}

// ── RefreshToken ──────────────────────────────────────────────────────────────

func TestRefreshToken_NoRefreshToken(t *testing.T) {
	svc := newTestService()
	cfg := newTestConfig(t, validAccessToken, "") // no refresh token

	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.RefreshToken(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for missing refresh token, got nil")
	}
	if !strings.Contains(err.Error(), "no refresh token") {
		t.Errorf("unexpected error message: %v", err)
	}
	t.Logf("✅ RefreshToken correctly rejected missing refresh token: %v", err)
}

func rejectingTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
	}))
}

func TestRefreshToken_ContextCancelled(t *testing.T) {
	server := rejectingTokenServer(t)
	defer server.Close()

	svc := auth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	done := make(chan error, 1)
	go func() { done <- svc.RefreshToken(ctx, cfg) }()

	select {
	case <-done:
		// Any return is acceptable; we only care that it returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshToken did not return within 5 s with cancelled context")
	}
}

func TestRefreshToken_ExpiredToken(t *testing.T) {
	server := rejectingTokenServer(t)
	defer server.Close()

	svc := auth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := svc.RefreshToken(ctx, cfg); err == nil {
		t.Fatal("expected RefreshToken to fail against a rejecting token endpoint, got nil")
	}
}

func TestRefreshToken_Concurrency(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()

	svc := auth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	const goroutines = 5
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = svc.RefreshToken(ctx, cfg)
		}(i)
	}
	wg.Wait()

	got := atomic.LoadInt64(&hits)
	if got < 1 {
		t.Errorf("expected the leader to perform the refresh, got %d requests", got)
	}
	if got >= goroutines {
		t.Errorf("single-flight failed: %d requests issued (expected one refresh cycle, not %d×attempts)", got, goroutines)
	}

	errCount := 0
	for _, err := range errs {
		if err != nil {
			errCount++
		}
	}
	if errCount == 0 {
		t.Error("expected the leader goroutine to return the refresh error")
	}
}
