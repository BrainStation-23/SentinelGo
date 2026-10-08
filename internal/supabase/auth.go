package supabase

import (
	"context"
	"errors"
	"fmt"
)

// Session is a GoTrue token pair.
type Session struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// RefreshSession exchanges refreshToken for a new session
// (POST /auth/v1/token?grant_type=refresh_token).
//
// The apikey header is the project's anon key and no Authorization header is
// sent: GoTrue authenticates this call by the refresh token alone. (The old
// supabase-go path sent the user's JWT as the apikey, which the gateway
// rejects.) Supabase rotates refresh tokens, so the caller must persist the
// returned pair.
func (c *Client) RefreshSession(ctx context.Context, refreshToken string) (*Session, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh session: no refresh token")
	}
	body, err := jsonBody(map[string]string{"refresh_token": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("refresh session: %w", err)
	}
	req, err := c.newJSONRequest(ctx, "/auth/v1/token?grant_type=refresh_token", body)
	if err != nil {
		return nil, err
	}
	c.setCommonHeaders(req, false)

	var s Session
	if err := doJSON(c.api, req, &s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" || s.RefreshToken == "" {
		return nil, errors.New("refresh session: response is missing tokens")
	}
	return &s, nil
}
