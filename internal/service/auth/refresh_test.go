package auth

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/resilience"
	"sentinelgo/internal/supabase"
)

// TestRefresh_SendsAnonKeyAndNoBearer pins the fix for the refresh bug: the
// old supabase-go path sent the user's JWT as the apikey, which the gateway
// rejects, so every recovery fell back to agent-login.
func TestRefresh_SendsAnonKeyAndNoBearer(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	var query string
	srv := recoveryServer(t, recoveryRoutes{
		refresh: func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got, query = r.Header.Clone(), r.URL.RawQuery
			mu.Unlock()
			okRefresh(w, r)
		},
		login: okLogin,
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	if err := svc.RefreshToken(context.Background(), cfg); err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Get("apikey") != "test-anon-key" {
		t.Errorf("apikey = %q, want the anon key (not the user JWT)", got.Get("apikey"))
	}
	if got.Get("Authorization") != "" {
		t.Errorf("Authorization = %q, want none", got.Get("Authorization"))
	}
	if query != "grant_type=refresh_token" {
		t.Errorf("query = %q, want grant_type=refresh_token", query)
	}
	if cfg.GetAccessToken() != "refreshed-access-token" || cfg.GetRefreshToken() != "refreshed-refresh-token" {
		t.Errorf("tokens not rotated: %q / %q", cfg.GetAccessToken(), cfg.GetRefreshToken())
	}
}

// A 4xx refresh (invalid_grant, already used) cannot succeed on retry with the
// same token, so it must not burn the 3 attempts and their backoff.
func TestRefresh_4xxIsTerminal(t *testing.T) {
	var hits int64
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: okLogin, refreshHit: &hits})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.RefreshToken(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected the rejected refresh to fail")
	}
	if supabase.StatusCode(err) != http.StatusBadRequest {
		t.Errorf("err = %v, want it to carry status 400", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("refresh attempts = %d, want 1 (4xx is terminal)", got)
	}
}

func TestRefresh_5xxIsRetried(t *testing.T) {
	var hits int64
	srv := recoveryServer(t, recoveryRoutes{
		refreshHit: &hits,
		refresh: func(w http.ResponseWriter, r *http.Request) {
			if atomic.LoadInt64(&hits) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			okRefresh(w, r)
		},
		login: okLogin,
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.RefreshToken(ctx, cfg); err != nil {
		t.Fatalf("RefreshToken should succeed after a transient 502: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Errorf("refresh attempts = %d, want 2", got)
	}
}

// After a successful recovery, a new one within the cooldown is refused
// without touching the network, so a token the backend keeps rejecting cannot
// loop 401 → recover → 401.
func TestRecover_CooldownAfterSuccess(t *testing.T) {
	var refreshHit, loginHit int64
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin, refreshHit: &refreshHit, loginHit: &loginHit})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)
	ctx := context.Background()

	if err := svc.Recover(ctx, cfg); err != nil {
		t.Fatalf("first Recover: %v", err)
	}
	before := atomic.LoadInt64(&refreshHit) + atomic.LoadInt64(&loginHit)
	if err := svc.Recover(ctx, cfg); !errors.Is(err, ErrRecoveryCooldown) {
		t.Fatalf("second Recover = %v, want ErrRecoveryCooldown", err)
	}
	if after := atomic.LoadInt64(&refreshHit) + atomic.LoadInt64(&loginHit); after != before {
		t.Errorf("cooldown Recover hit the network (%d → %d requests)", before, after)
	}

	prev := recoverCooldown
	recoverCooldown = 0
	t.Cleanup(func() { recoverCooldown = prev })
	if err := svc.Recover(ctx, cfg); err != nil {
		t.Errorf("Recover after the cooldown: %v", err)
	}
}

// A request still rejected with 401 straight after a successful recovery is
// counted against the breaker.
func TestDoWithAuthRetry_Still401AfterRecoveryCountsAgainstBreaker(t *testing.T) {
	srv := recoveryServer(t, recoveryRoutes{refresh: okRefresh, login: okLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	unauthorized := &supabase.APIError{Status: 401, Code: "PGRST301", Method: "POST", Path: "/rest/v1/rpc/f"}
	err := svc.DoWithAuthRetry(context.Background(), cfg, func() error { return unauthorized })
	if !errors.Is(err, unauthorized) {
		t.Fatalf("err = %v, want the 401", err)
	}
	if stats := svc.breaker.GetStats(); stats.Failures != 1 {
		t.Errorf("breaker failures = %d, want 1", stats.Failures)
	}
	if svc.breaker.GetState() != resilience.StateClosed {
		t.Errorf("one failure must not open the breaker")
	}
}

// LoginInMemory (used by the CLI) updates the in-memory tokens but never
// writes them, so a one-off command cannot clobber the service's tokens.
func TestLoginInMemory_DoesNotPersist(t *testing.T) {
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: okLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)
	before, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.LoginInMemory(context.Background(), cfg); err != nil {
		t.Fatalf("LoginInMemory: %v", err)
	}
	if cfg.GetAccessToken() != "login-access-token" {
		t.Errorf("in-memory token = %q, want login-access-token", cfg.GetAccessToken())
	}
	after, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("LoginInMemory wrote the config file")
	}
}
