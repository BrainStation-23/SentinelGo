package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Covers the Login/doLoginRequest branches not already exercised by
// recovery_test.go's success/reject/retry/rate-limit cases.

func TestLogin_NilConfig(t *testing.T) {
	svc := NewService("https://test.supabase.co", "test-anon-key")
	err := svc.Login(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "config is nil") {
		t.Fatalf("err = %v, want an error mentioning \"config is nil\"", err)
	}
}

func TestLogin_EmptyBaseURL(t *testing.T) {
	svc := NewService("", "test-anon-key")
	cfg := recoveryConfig(t, "")

	err := svc.Login(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "base URL not configured") {
		t.Fatalf("err = %v, want an error mentioning \"base URL not configured\"", err)
	}
}

func TestLogin_MalformedJSONResponse(t *testing.T) {
	fastRetries(t)
	srv := recoveryServer(t, recoveryRoutes{
		refresh: failRefresh,
		login: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not valid json`))
		},
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an error for a malformed JSON response body")
	}
}

func TestLogin_EmptyAccessTokenInResponse(t *testing.T) {
	fastRetries(t)
	srv := recoveryServer(t, recoveryRoutes{
		refresh: failRefresh,
		login: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"","refresh_token":"r","expires_in":3600}`))
		},
	})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)

	err := svc.Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an error when the agent-login response has an empty access_token")
	}
}

func TestLogin_SucceedsButPersistenceFails(t *testing.T) {
	srv := recoveryServer(t, recoveryRoutes{refresh: failRefresh, login: okLogin})
	svc := NewService(srv.URL, "test-anon-key")
	cfg := recoveryConfig(t, srv.URL)
	// validateConfig requires SupabaseKey; clearing it makes SaveAtomic fail
	// deterministically after a successful login, without touching the filesystem.
	cfg.SupabaseKey = ""

	err := svc.Login(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected an error when persisting the rotated tokens fails")
	}
	if !strings.Contains(err.Error(), "failed to persist tokens") {
		t.Errorf("err = %v, want it to mention persistence failure", err)
	}
	// The login itself must still have gone through and updated the in-memory token.
	if cfg.GetAccessToken() != "login-access-token" {
		t.Errorf("access token = %q, want login-access-token even though persistence failed", cfg.GetAccessToken())
	}
}
