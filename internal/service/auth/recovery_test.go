package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/resilience"
)

// This is a white-box test (package auth) so it can drop maxRetries to 1 — that
// removes the multi-second inter-attempt backoff and keeps the breaker/recovery
// tests fast and deterministic.

// fastRetries sets maxRetries to 1 for the duration of a test and restores it.
func fastRetries(t *testing.T) {
	t.Helper()
	prev := maxRetries
	maxRetries = 1
	t.Cleanup(func() { maxRetries = prev })
}

// recoveryRoutes lets each test script how the fake Supabase answers a gotrue
// token refresh versus an agent-login.
type recoveryRoutes struct {
	refresh    http.HandlerFunc
	login      http.HandlerFunc
	refreshHit *int64
	loginHit   *int64
}

func recoveryServer(t *testing.T, r recoveryRoutes) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.Contains(req.URL.Path, "agent-login"):
			if r.loginHit != nil {
				atomic.AddInt64(r.loginHit, 1)
			}
			r.login(w, req)
		case strings.Contains(req.URL.Path, "/token"):
			if r.refreshHit != nil {
				atomic.AddInt64(r.refreshHit, 1)
			}
			r.refresh(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func okRefresh(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"refreshed-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"refreshed-refresh-token","user":{"id":"00000000-0000-0000-0000-000000000001"}}`))
}

func failRefresh(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
}

func okLogin(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"login-access-token","refresh_token":"login-refresh-token","expires_in":3600}`))
}

func rejectLogin(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid agent credentials"}`))
}

func failLogin5xx(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"temporary"}`))
}

func rateLimitLogin(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"Too many failed attempts. Try again later."}`))
}

func recoveryConfig(t *testing.T, baseURL string) *config.Config {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "recovery-config-*.json")
	if err != nil {
		t.Fatalf("temp config: %v", err)
	}
	_ = f.Close()
	return &config.Config{
		Path:         f.Name(),
		SupabaseURL:  baseURL,
		SupabaseKey:  "test-anon-key",
		DeviceID:     "09ef2eaf-ed10-431a-b4b4-f5e0f4b36829",
		AgentID:      "agent-123",
		AgentSecret:  "secret-abc",
		AccessToken:  "stale-access-token",
		RefreshToken: "stale-refresh-token",
	}
}

// ── Login ──────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: okLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	if err := svc.Login(context.Background(), cfg); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if cfg.GetAccessToken() != "login-access-token" {
		t.Errorf("access token = %q, want login-access-token", cfg.GetAccessToken())
	}
	if cfg.RefreshToken != "login-refresh-token" {
		t.Errorf("refresh token = %q, want login-refresh-token", cfg.RefreshToken)
	}
}

func TestLogin_RejectedCredentials(t *testing.T) {
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: rejectLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for rejected credentials")
	}
	if !errors.Is(err, ErrLoginRejected) {
		t.Errorf("error = %v, want ErrLoginRejected", err)
	}
}

func TestLogin_MissingCredentials(t *testing.T) {
	svc := NewService("https://test.supabase.co", "test-anon-key")
	cfg := recoveryConfig(t, "https://test.supabase.co")
	cfg.AgentSecret = ""

	if err := svc.Login(context.Background(), cfg); err == nil {
		t.Fatal("expected error when agent_secret is empty")
	}
}

func TestLogin_RetriesTransientThenSucceeds(t *testing.T) {
	var loginHit int64
	srv := recoveryServer(t, recoveryRoutes{
		refresh:  failRefresh,
		loginHit: &loginHit,
		login: func(w http.ResponseWriter, req *http.Request) {
			if atomic.LoadInt64(&loginHit) == 1 {
				failLogin5xx(w, req) // first attempt: transient
				return
			}
			okLogin(w, req) // subsequent attempts succeed
		},
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := svc.Login(ctx, cfg); err != nil {
		t.Fatalf("Login should succeed after a transient failure: %v", err)
	}
	if got := atomic.LoadInt64(&loginHit); got < 2 {
		t.Errorf("expected at least 2 login attempts (transient then success), got %d", got)
	}
}

func TestLogin_RateLimited_NoRetry(t *testing.T) {
	var loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: rateLimitLogin, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error when rate limited")
	}
	if errors.Is(err, ErrLoginRejected) {
		t.Error("rate-limit (429) must NOT be treated as a credential rejection")
	}
	// A 429 must not be retried in a tight loop: the server logs a failed attempt
	// per request, so retrying would extend the lockout.
	if got := atomic.LoadInt64(&loginHit); got != 1 {
		t.Errorf("expected exactly 1 agent-login attempt on 429 (no retry), got %d", got)
	}
}

// ── Recover ──────────────────────────────────────────────────────────────────

func TestRecover_RefreshSucceeds_NoLogin(t *testing.T) {
	var loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	if err := svc.Recover(context.Background(), cfg); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if cfg.GetAccessToken() != "refreshed-access-token" {
		t.Errorf("access token = %q, want refreshed-access-token", cfg.GetAccessToken())
	}
	if atomic.LoadInt64(&loginHit) != 0 {
		t.Errorf("agent-login should not be called when refresh succeeds, hits=%d", loginHit)
	}
	if !svc.Healthy() {
		t.Error("service should be healthy after a successful refresh")
	}
}

func TestRecover_RefreshFails_LoginSucceeds(t *testing.T) {
	fastRetries(t)
	var loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: okLogin, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	if err := svc.Recover(context.Background(), cfg); err != nil {
		t.Fatalf("Recover should fall back to agent-login: %v", err)
	}
	if cfg.GetAccessToken() != "login-access-token" {
		t.Errorf("access token = %q, want login-access-token", cfg.GetAccessToken())
	}
	if atomic.LoadInt64(&loginHit) == 0 {
		t.Error("agent-login should have been called after refresh failed")
	}
	if svc.NeedsReprovision() {
		t.Error("NeedsReprovision should be false after a successful login")
	}
}

func TestRecover_LoginRejected_NeedsReprovision(t *testing.T) {
	fastRetries(t)
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: rejectLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.Recover(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected Recover to fail when credentials are rejected")
	}
	if !svc.NeedsReprovision() {
		t.Error("NeedsReprovision should be true after agent-login rejection")
	}
	if svc.Healthy() {
		t.Error("service should be unhealthy after agent-login rejection")
	}
}

func TestRecover_BreakerOpensAndStopsHammering(t *testing.T) {
	fastRetries(t)
	var refreshHit, loginHit int64
	srv := recoveryServer(t, recoveryRoutes{
		refresh:    failRefresh,  // refresh always fails
		login:      failLogin5xx, // login always transient-fails (NOT a rejection)
		refreshHit: &refreshHit,
		loginHit:   &loginHit,
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	ctx := context.Background()
	// Drive enough failures to open the breaker (authBreakerMaxFailures).
	for i := 0; i < authBreakerMaxFailures; i++ {
		if err := svc.Recover(ctx, cfg); err == nil {
			t.Fatalf("Recover attempt %d should have failed", i)
		}
	}
	if svc.breaker.GetState() != resilience.StateOpen {
		t.Fatalf("breaker state = %v, want open after %d failures", svc.breaker.GetState(), authBreakerMaxFailures)
	}

	hitsBefore := atomic.LoadInt64(&refreshHit) + atomic.LoadInt64(&loginHit)

	// Further Recover calls while open must NOT reach the server.
	for i := 0; i < 5; i++ {
		_ = svc.Recover(ctx, cfg)
	}
	hitsAfter := atomic.LoadInt64(&refreshHit) + atomic.LoadInt64(&loginHit)

	if hitsAfter != hitsBefore {
		t.Errorf("breaker open but server still hit: before=%d after=%d (hammering not stopped)", hitsBefore, hitsAfter)
	}
	if svc.Healthy() {
		t.Error("service should report unhealthy while breaker is open")
	}
}

// ── DoWithAuthRetry ──────────────────────────────────────────────────────────

func TestDoWithAuthRetry_401_RecoversAndRetries(t *testing.T) {
	fastRetries(t)
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	calls := 0
	err := svc.DoWithAuthRetry(context.Background(), cfg, func() error {
		calls++
		if calls == 1 {
			return errors.New("authentication failed: status 401")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DoWithAuthRetry: %v", err)
	}
	if calls != 2 {
		t.Errorf("fn called %d times, want 2 (initial 401 + one retry)", calls)
	}
}

func TestDoWithAuthRetry_403_NoRecovery(t *testing.T) {
	var refreshHit, loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin, refreshHit: &refreshHit, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	calls := 0
	err := svc.DoWithAuthRetry(context.Background(), cfg, func() error {
		calls++
		return errors.New("unexpected status 403: forbidden")
	})
	if err == nil {
		t.Fatal("expected the 403 error to propagate")
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1 (403 must not trigger recovery/retry)", calls)
	}
	if atomic.LoadInt64(&refreshHit)+atomic.LoadInt64(&loginHit) != 0 {
		t.Error("403 must not trigger any recovery network calls")
	}
}

func TestDoWithAuthRetry_Success_NoRecovery(t *testing.T) {
	var refreshHit, loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin, refreshHit: &refreshHit, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	calls := 0
	err := svc.DoWithAuthRetry(context.Background(), cfg, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("DoWithAuthRetry: %v", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
	if atomic.LoadInt64(&refreshHit)+atomic.LoadInt64(&loginHit) != 0 {
		t.Error("a successful call must not trigger recovery")
	}
}
