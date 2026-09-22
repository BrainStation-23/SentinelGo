package auth_test

import (
	"errors"
	"testing"

	"sentinelgo/internal/service/auth"
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

// TestUnauthorizedOutranksForbidden covers the ordering fix in IsUnauthorized.
//
// isForbidden matches the bare word "forbidden" anywhere in the message. It used
// to be consulted first, so a real 401 whose response body happened to contain
// that word was classified as a policy denial. IsUnauthorized then returned
// false, DoWithAuthRetry skipped recovery, and because nothing else retries the
// session the agent stopped reporting until it was restarted.
func TestUnauthorizedOutranksForbidden(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantUnauth    bool
		wantForbidden bool
	}{
		{
			name:          "401 whose body mentions forbidden",
			err:           errors.New(`status 401: {"msg":"forbidden to use this endpoint"}`),
			wantUnauth:    true,
			wantForbidden: false,
		},
		{
			name:          "expired JWT alongside permission denied",
			err:           errors.New("PGRST301 jwt expired: permission denied for table agents"),
			wantUnauth:    true,
			wantForbidden: false,
		},
		{
			name:          "plain 403 still reads as forbidden",
			err:           errors.New("status 403: permission denied"),
			wantUnauth:    false,
			wantForbidden: true,
		},
		{
			name:          "RLS denial still reads as forbidden",
			err:           errors.New("new row violates row-level security policy"),
			wantUnauth:    false,
			wantForbidden: true,
		},
		{
			name:          "plain 401 unchanged",
			err:           errors.New("authentication failed: status 401"),
			wantUnauth:    true,
			wantForbidden: false,
		},
		{
			name:          "unrelated error is neither",
			err:           errors.New("connection reset by peer"),
			wantUnauth:    false,
			wantForbidden: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auth.IsUnauthorized(tt.err); got != tt.wantUnauth {
				t.Errorf("IsUnauthorized(%v) = %v, want %v", tt.err, got, tt.wantUnauth)
			}
			if got := auth.IsForbidden(tt.err); got != tt.wantForbidden {
				t.Errorf("IsForbidden(%v) = %v, want %v", tt.err, got, tt.wantForbidden)
			}
			// The two classifications must never both be true: DoWithAuthRetry
			// branches on exactly one of them.
			if auth.IsUnauthorized(tt.err) && auth.IsForbidden(tt.err) {
				t.Errorf("error classified as both unauthorized and forbidden: %v", tt.err)
			}
		})
	}
}
