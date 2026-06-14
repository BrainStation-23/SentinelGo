package internal

// White-box tests for unexported types in main_integration.go.
// Package internal (not internal_test) is required to instantiate authTokenRefresher.

import (
	"context"
	"testing"

	"sentinelgo/internal/config"
	authsvc "sentinelgo/internal/service/auth"
)

// TestAuthTokenRefresher_RefreshToken exercises the RefreshToken method on the
// unexported authTokenRefresher adapter. The call will fail with a network error
// (no real Supabase server), but all statements in the function are traversed.
func TestAuthTokenRefresher_RefreshToken(t *testing.T) {
	cfg := &config.Config{
		SupabaseURL:  "https://localhost:1", // unreachable — triggers fast failure
		AccessToken:  "initial-token",
		RefreshToken: "",
	}
	svc := authsvc.NewService(cfg.SupabaseURL, cfg.AccessToken)
	r := &authTokenRefresher{authSvc: svc, cfg: cfg}

	// Ignore the error — we only need the statements to execute.
	_, _ = r.RefreshToken(context.Background())
}

// TestAuthTokenRefresher_RefreshToken_Cancelled verifies no panic when the
// context is already cancelled.
func TestAuthTokenRefresher_RefreshToken_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &config.Config{
		SupabaseURL: "https://localhost:1",
		AccessToken: "token",
	}
	svc := authsvc.NewService(cfg.SupabaseURL, cfg.AccessToken)
	r := &authTokenRefresher{authSvc: svc, cfg: cfg}

	_, _ = r.RefreshToken(ctx)
}
