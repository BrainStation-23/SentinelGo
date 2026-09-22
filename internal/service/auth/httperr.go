package auth

import (
	"context"
	"errors"
	"net"
	"strings"
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
func IsUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())

	// Unambiguous 401 markers win outright, and are checked before the 403
	// heuristic. Order matters here: isForbidden matches the bare word
	// "forbidden" anywhere in the message, so a genuine 401 whose response body
	// happens to contain that word would otherwise be read as a policy denial.
	// That suppresses recovery, and because nothing else re-tries the session,
	// the agent parks itself until a restart.
	if isExplicitlyUnauthorized(s) {
		return true
	}
	if isForbidden(s) {
		// Authenticated but forbidden — refreshing the token won't help.
		return false
	}
	return strings.Contains(s, "unauthorized")
}

// isExplicitlyUnauthorized matches the markers that only ever accompany a 401,
// as opposed to the bare word "unauthorized" which can appear in either.
func isExplicitlyUnauthorized(lower string) bool {
	return strings.Contains(lower, "status 401") ||
		strings.Contains(lower, "401 unauthorized") ||
		strings.Contains(lower, "jwt expired") ||
		strings.Contains(lower, "jwtexpired") ||
		strings.Contains(lower, "pgrst301") || // PostgREST: JWT expired
		strings.Contains(lower, "invalid jwt") ||
		strings.Contains(lower, "token is expired") ||
		strings.Contains(lower, "invalid_grant")
}

// IsForbidden reports whether err looks like an HTTP 403 / policy denial.
func IsForbidden(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// Symmetric with IsUnauthorized: an explicit 401 marker outranks the loose
	// 403 heuristic, so the two can never both report true for one error.
	if isExplicitlyUnauthorized(s) {
		return false
	}
	return isForbidden(s)
}

// isRefreshTokenUnused reports whether err proves the refresh token never
// reached the server, making it safe to send the same token again.
//
// Supabase rotates the refresh token on every successful exchange. If the
// request was delivered and the server rotated, but the response was lost in
// flight, the token we still hold is already spent: re-sending it cannot
// succeed, and once GoTrue refresh-token reuse detection is enabled it is read
// as a replay and revokes the whole session family. So the question is not "was
// this error transient" but "is the token definitely still valid" — and only
// failures that happen before any byte is written can answer yes.
//
// Anything ambiguous returns false, which is also what happens if an SDK
// flattens the error chain and defeats errors.As. The caller then falls back to
// agent-login, which re-establishes a session from agent_id + agent_secret.
func isRefreshTokenUnused(err error) bool {
	if err == nil {
		return false
	}

	// A deadline or cancellation says nothing about how far the request got.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	// The question throughout is "was a connection ever established", because
	// only then could the request have been delivered.

	// Name resolution fails before any connection exists.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// A dial failure means the TCP connection never came up, so no request was
	// written. This is checked before the timeout case below on purpose: a dial
	// timeout is still a dial failure, and is safe to retry.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial"
	}

	// Any other timeout may have fired after the request went out.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	return false
}

func isForbidden(lower string) bool {
	return strings.Contains(lower, "status 403") ||
		strings.Contains(lower, "403 forbidden") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "row-level security") ||
		strings.Contains(lower, "row level security")
}
