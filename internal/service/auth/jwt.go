package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenExpiry parses the `exp` (expiration) claim from a JWT and returns it as a
// time.Time. The signature is NOT verified — the Supabase backend is the
// authority on validity; the agent only needs the expiry to schedule a
// proactive refresh before the token lapses.
func TokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("not a JWT: expected 3 segments, got %d", len(parts))
	}

	// JWTs use base64url without padding, but tolerate padded variants too.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return time.Time{}, fmt.Errorf("decode payload: %w", err)
		}
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("token has no exp claim")
	}

	return time.Unix(claims.Exp, 0), nil
}

// ShouldRefresh reports whether the access token should be refreshed now. It
// returns true when the token is empty, cannot be parsed, is already expired, or
// will expire within skew. This replaces the previous time-since-last-check
// heuristic, which never fired and let the token silently expire ~1h after
// startup, halting all reporting.
func ShouldRefresh(token string, skew time.Duration) bool {
	if token == "" {
		return true
	}
	exp, err := TokenExpiry(token)
	if err != nil {
		// Unparseable token: refresh to be safe rather than risk operating with
		// an expired credential.
		return true
	}
	return time.Now().Add(skew).After(exp)
}
