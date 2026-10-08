package auth

import (
	"strings"

	"sentinelgo/internal/supabase"
)

// This file centralizes the heuristics for deciding whether an error returned by
// a Supabase call means "your token is no longer accepted" (401 → try to
// recover the session) versus "you are authenticated but not allowed to do
// this" (403 → recovering the token changes nothing, so don't).
//
// The agent talks to Supabase through three different layers — the PostgREST
// SDK (agent_push_inventory, agent_upsert_software, audit-log batch), a
// hand-rolled HTTP client (taskstore), and gotrue (token refresh) — and each
// surfaces auth failures as a differently-shaped string. Rather than teach every
// call site how to recognise a 401, callers wrap their request in
// Service.DoWithAuthRetry and these helpers do the classification once.

// IsUnauthorized reports whether err looks like an HTTP 401 / expired-or-invalid
// token. An explicit 403 is deliberately NOT treated as unauthorized.
//
// Errors from internal/supabase carry the real status and code, so their
// verdict is final. The string heuristics below only apply to errors from the
// paths not yet migrated to that client; they are removed in Supabase P5.
func IsUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := supabase.AsAPIError(err); ok {
		return supabase.IsUnauthorized(err)
	}
	s := strings.ToLower(err.Error())
	if isForbidden(s) {
		// Authenticated but forbidden — refreshing the token won't help.
		return false
	}
	return strings.Contains(s, "status 401") ||
		strings.Contains(s, "401 unauthorized") ||
		strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "jwt expired") ||
		strings.Contains(s, "jwtexpired") ||
		strings.Contains(s, "pgrst301") || // PostgREST: JWT expired
		strings.Contains(s, "invalid jwt") ||
		strings.Contains(s, "token is expired") ||
		strings.Contains(s, "invalid_grant")
}

// IsForbidden reports whether err looks like an HTTP 403 / policy denial.
func IsForbidden(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := supabase.AsAPIError(err); ok {
		return supabase.IsForbidden(err)
	}
	return isForbidden(strings.ToLower(err.Error()))
}

func isForbidden(lower string) bool {
	return strings.Contains(lower, "status 403") ||
		strings.Contains(lower, "403 forbidden") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "row-level security") ||
		strings.Contains(lower, "row level security")
}
