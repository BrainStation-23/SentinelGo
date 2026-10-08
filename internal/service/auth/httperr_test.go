package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"sentinelgo/internal/service/auth"
	"sentinelgo/internal/supabase"
)

func apiErr(status int, code, msg string) error {
	return fmt.Errorf("wrapped: %w", &supabase.APIError{Status: status, Code: code, Message: msg, Method: "POST", Path: "/rest/v1/rpc/f"})
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"401", apiErr(401, "", ""), true},
		{"postgrest jwt expired", apiErr(401, "PGRST301", "JWT expired"), true},
		{"storage expired jwt", apiErr(400, "InvalidJWT", "jwt expired"), true},
		{"gotrue bad_jwt", apiErr(403, "bad_jwt", "invalid JWT"), true},
		{"403 is not 401", apiErr(403, "", "forbidden"), false},
		{"permission denied is not 401", apiErr(403, "42501", "permission denied for table agents"), false},
		{"500 server error", apiErr(500, "", ""), false},
		{"network error", errors.New("dial tcp: connection refused"), false},
		{"timeout", context.DeadlineExceeded, false},
		// Strings are no longer classified: the old substring heuristics are gone.
		{"plain string mentioning 401", errors.New("authentication failed: status 401"), false},
		{"plain string mentioning jwt expired", errors.New("PGRST301: JWT expired"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auth.IsUnauthorized(tt.err); got != tt.want {
				t.Errorf("IsUnauthorized(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsForbidden(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"403", apiErr(403, "", "forbidden"), true},
		{"42501", apiErr(403, "42501", "permission denied for table agents"), true},
		{"401 is not 403", apiErr(401, "PGRST301", ""), false},
		{"500", apiErr(500, "", ""), false},
		{"plain string mentioning forbidden", errors.New("unexpected status 403: forbidden"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auth.IsForbidden(tt.err); got != tt.want {
				t.Errorf("IsForbidden(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// A 401 whose body mentions row-level security must still trigger recovery,
// and a 403 must not, whatever its text says — the old substring checks got
// both wrong.
func TestClassification_IgnoresMessageText(t *testing.T) {
	rls401 := apiErr(401, "PGRST301", "JWT expired (row-level security)")
	if !auth.IsUnauthorized(rls401) || auth.IsForbidden(rls401) {
		t.Errorf("401 mentioning RLS: IsUnauthorized=%v IsForbidden=%v, want true/false", auth.IsUnauthorized(rls401), auth.IsForbidden(rls401))
	}
	forbidden := apiErr(403, "42501", "unauthorized: permission denied")
	if auth.IsUnauthorized(forbidden) || !auth.IsForbidden(forbidden) {
		t.Errorf("403 mentioning 'unauthorized': IsUnauthorized=%v IsForbidden=%v, want false/true", auth.IsUnauthorized(forbidden), auth.IsForbidden(forbidden))
	}
}
