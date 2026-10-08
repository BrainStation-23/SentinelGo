package auth

import "sentinelgo/internal/supabase"

// IsUnauthorized reports whether err is a Supabase rejection of the access
// token (HTTP 401, or a JWT error code such as PGRST301 or Storage's 400
// InvalidJWT), meaning a session refresh may fix it. A 403 is deliberately not
// unauthorized.
//
// Only typed errors from internal/supabase are classified. Every Supabase call
// goes through that client, so anything else (a network failure, a timeout, a
// local error) is not an auth failure — there is no string matching.
func IsUnauthorized(err error) bool {
	return supabase.IsUnauthorized(err)
}

// IsForbidden reports whether err is an authorization denial (HTTP 403 or
// Postgres 42501) for a token that was accepted, so refreshing it would not
// help.
func IsForbidden(err error) bool {
	return supabase.IsForbidden(err)
}
