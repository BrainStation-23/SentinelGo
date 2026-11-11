package adminpassword

import (
	"context"
	"encoding/json"

	"sentinelgo/internal/supabase"
)

// RPC is the Supabase RPC call (supabase.Client.RPC); an interface so tests
// can fake the server.
type RPC interface {
	RPC(ctx context.Context, fn string, params, out any, opts ...supabase.CallOption) error
}

// Client implements Server over internal/supabase. client is called per
// request, so each call carries the current access token. Callers wrap
// calls in auth.Service.DoWithAuthRetry (the Rotator's Retry).
type Client struct{ client func() RPC }

// NewClient returns a Client.
func NewClient(client func() RPC) *Client { return &Client{client: client} }

// FetchPolicy calls agent_get_admin_password_policy. status nil sends
// p_status null.
func (c *Client) FetchPolicy(ctx context.Context, knownVersion string, status *Status) (PolicyResponse, error) {
	params := struct {
		KnownVersion *string         `json:"p_known_version"`
		Status       json.RawMessage `json:"p_status"`
	}{Status: json.RawMessage("null")}
	if knownVersion != "" {
		params.KnownVersion = &knownVersion
	}
	if status != nil {
		data, err := status.Encode()
		if err != nil {
			return PolicyResponse{}, err
		}
		params.Status = data
	}
	var raw []byte
	if err := c.client().RPC(ctx, RPCGetPolicy, params, &raw); err != nil {
		return PolicyResponse{}, err
	}
	return DecodePolicyResponse(raw)
}

// Escrow calls agent_escrow_admin_password. The response body isn't needed:
// any non-error answer means the server stored the password.
func (c *Client) Escrow(ctx context.Context, e Escrow) error {
	var raw []byte
	return c.client().RPC(ctx, RPCEscrow, map[string]any{"p_payload": e}, &raw)
}

// Confirm calls agent_confirm_admin_password.
func (c *Client) Confirm(ctx context.Context, cf Confirm) error {
	var raw []byte
	return c.client().RPC(ctx, RPCConfirm, map[string]any{"p_payload": cf}, &raw)
}
