package auth

import "strings"

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
// String matching is used instead of typed errors because the three client
// layers (postgrest-go SDK, hand-rolled HTTP taskstore client, and gotrue token
// refresh) each surface auth failures as differently-shaped error strings with
// no shared error type. Centralising the heuristics here means every call site
// gets consistent classification without requiring changes across all three
// layers. The patterns are tested in httperr_test.go; extend them there when
// new error shapes are observed in production.
func IsUnauthorized(err error) bool {
	if err == nil {
		return false
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
