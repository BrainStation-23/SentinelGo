package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	serviceauth "sentinelgo/internal/service/auth"
)

func cfgWithToken(token string) *config.Config {
	return &config.Config{
		SupabaseURL:  "https://example.supabase.co",
		SupabaseKey:  "test-key",
		DeviceID:     "test-device",
		AccessToken:  token,
		RefreshToken: "refresh-token",
	}
}

func TestIsAuthenticated_EmptyToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken(""), nil)
	if sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = true with empty token, want false")
	}
}

func TestIsAuthenticated_WithToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken("my-valid-token"), nil)
	if !sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = false with non-empty token, want true")
	}
}

func TestIsAuthenticated_NilConfig(t *testing.T) {
	sm := serviceauth.NewSessionManager(nil, nil)
	if sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = true with nil config, want false")
	}
}

func TestGetAccessToken_WithToken(t *testing.T) {
	want := "my-access-token"
	sm := serviceauth.NewSessionManager(cfgWithToken(want), nil)
	got := sm.GetAccessToken()
	if got != want {
		t.Errorf("GetAccessToken() = %q, want %q", got, want)
	}
}

func TestGetAccessToken_EmptyToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken(""), nil)
	got := sm.GetAccessToken()
	if got != "" {
		t.Errorf("GetAccessToken() = %q, want %q", got, "")
	}
}

func TestGetAccessToken_NilConfig(t *testing.T) {
	sm := serviceauth.NewSessionManager(nil, nil)
	got := sm.GetAccessToken()
	if got != "" {
		t.Errorf("GetAccessToken() with nil config = %q, want %q", got, "")
	}
}

// ── InitializeSession ─────────────────────────────────────────────────────────

func TestInitializeSession_EmptyToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken(""), newTestService())
	err := sm.InitializeSession()
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if !strings.Contains(err.Error(), "no access token") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestInitializeSession_Success(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken("my-valid-token"), newTestService())
	if err := sm.InitializeSession(); err != nil {
		t.Fatalf("InitializeSession() unexpected error: %v", err)
	}
}

func TestInitializeSession_SetSessionFails(t *testing.T) {
	// Service created with empty baseURL: SetSession returns "base URL not configured".
	svc := serviceauth.NewService("", "")
	sm := serviceauth.NewSessionManager(cfgWithToken("some-token"), svc)
	err := sm.InitializeSession()
	if err == nil {
		t.Fatal("expected error when SetSession fails, got nil")
	}
	if !strings.Contains(err.Error(), "set session") {
		t.Errorf("expected 'set session' in error, got: %v", err)
	}
}

// ── RefreshTokens ─────────────────────────────────────────────────────────────

func TestRefreshTokens_NilConfig(t *testing.T) {
	sm := serviceauth.NewSessionManager(nil, newTestService())
	err := sm.RefreshTokens(context.Background())
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
	if !strings.Contains(err.Error(), "not initialised") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRefreshTokens_ServiceError(t *testing.T) {
	server := rejectingTokenServer(t)
	defer server.Close()

	svc := serviceauth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession: %v", err)
	}

	sm := serviceauth.NewSessionManager(cfg, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := sm.RefreshTokens(ctx)
	if err == nil {
		t.Fatal("expected error from rejecting server, got nil")
	}
	if !strings.Contains(err.Error(), "refresh tokens") {
		t.Errorf("expected 'refresh tokens' in error, got: %v", err)
	}
}

func TestRefreshTokens_ContextCancelled(t *testing.T) {
	server := rejectingTokenServer(t)
	defer server.Close()

	svc := serviceauth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession: %v", err)
	}

	sm := serviceauth.NewSessionManager(cfg, svc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	done := make(chan error, 1)
	go func() { done <- sm.RefreshTokens(ctx) }()

	select {
	case err := <-done:
		// Returned promptly — verify the error reflects context cancellation.
		if err == nil {
			t.Error("expected non-nil error for cancelled context, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshTokens did not return within 5s with cancelled context")
	}
}

// successTokenServer returns an httptest.Server that responds to any request
// with a gotrue-format token response, simulating a successful Supabase token
// refresh endpoint.
func successTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "refreshed-access-token",
			"token_type": "bearer",
			"expires_in": 3600,
			"refresh_token": "refreshed-refresh-token",
			"user": {
				"id": "00000000-0000-0000-0000-000000000001",
				"email": "test@example.com"
			}
		}`))
	}))
}

// TestRefreshTokens_Success verifies the happy path: a mock server returns valid
// tokens and RefreshTokens updates cfg.AccessToken accordingly.
func TestRefreshTokens_Success(t *testing.T) {
	server := successTokenServer(t)
	defer server.Close()

	svc := serviceauth.NewService(server.URL, "")
	cfg := newTestConfig(t, validAccessToken, validRefreshToken)
	cfg.SupabaseKey = "test-key" // required by config validation when persisting refreshed tokens
	if err := svc.InitSession(cfg); err != nil {
		t.Fatalf("InitSession: %v", err)
	}

	sm := serviceauth.NewSessionManager(cfg, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := sm.RefreshTokens(ctx); err != nil {
		t.Fatalf("RefreshTokens() unexpected error: %v", err)
	}
	if cfg.AccessToken != "refreshed-access-token" {
		t.Errorf("AccessToken = %q, want %q", cfg.AccessToken, "refreshed-access-token")
	}
}
