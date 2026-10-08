package auth_test

import (
	"errors"
	"testing"

	"sentinelgo/internal/service/auth"
	"sentinelgo/internal/supabase"
)

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"taskstore 401", errors.New("authentication failed: status 401"), true},
		{"generic 401", errors.New("unexpected status 401: bad jwt"), true},
		{"postgrest jwt expired", errors.New("PGRST301: JWT expired"), true},
		{"gotrue invalid_grant", errors.New("refresh failed: invalid_grant"), true},
		{"403 is not 401", errors.New("unexpected status 403: forbidden"), false},
		{"permission denied is not 401", errors.New("permission denied for table agents"), false},
		{"500 server error", errors.New("unexpected status 500"), false},
		{"network error", errors.New("dial tcp: connection refused"), false},
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
		{"403", errors.New("unexpected status 403: forbidden"), true},
		{"permission denied", errors.New("permission denied for table agents"), true},
		{"rls", errors.New("new row violates row-level security policy"), true},
		{"401 is not 403", errors.New("authentication failed: status 401"), false},
		{"500", errors.New("unexpected status 500"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auth.IsForbidden(tt.err); got != tt.want {
				t.Errorf("IsForbidden(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestClassification_APIErrorVerdictIsFinal guards the case the legacy
// substring checks get wrong: a 401 whose body mentions row-level security
// must still trigger recovery, and a 403 must not, whatever its text says.
func TestClassification_APIErrorVerdictIsFinal(t *testing.T) {
	rls401 := &supabase.APIError{Status: 401, Code: "PGRST301", Message: "JWT expired (row-level security)", Method: "POST", Path: "/rest/v1/rpc/f"}
	if !auth.IsUnauthorized(rls401) || auth.IsForbidden(rls401) {
		t.Errorf("401 mentioning RLS: IsUnauthorized=%v IsForbidden=%v, want true/false", auth.IsUnauthorized(rls401), auth.IsForbidden(rls401))
	}
	forbidden := &supabase.APIError{Status: 403, Code: "42501", Message: "unauthorized: permission denied", Method: "POST", Path: "/rest/v1/rpc/f"}
	if auth.IsUnauthorized(forbidden) || !auth.IsForbidden(forbidden) {
		t.Errorf("403 mentioning 'unauthorized': IsUnauthorized=%v IsForbidden=%v, want false/true", auth.IsUnauthorized(forbidden), auth.IsForbidden(forbidden))
	}
}
