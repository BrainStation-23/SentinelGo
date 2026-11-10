package packages

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/supabase"
)

const (
	rpcGetSettings = "agent_get_package_settings"
	rpcEnqueue     = "agent_enqueue_packages"
)

// Settings is the server's package inventory settings.
type Settings struct {
	Version string `json:"version"`
	// Enabled false means collect nothing.
	Enabled bool `json:"enabled"`
	// ProjectScan false means global installs only.
	ProjectScan bool `json:"project_scan"`
	// Roots are the folders a project scan walks; empty means each user's
	// home directory.
	Roots []string `json:"roots"`
	// MaxDepth is how deep a project scan walks below a root.
	MaxDepth int `json:"max_depth"`
}

// RPC is the Supabase RPC call (supabase.Client.RPC); an interface so tests
// can fake the server.
type RPC interface {
	RPC(ctx context.Context, fn string, params, out any, opts ...supabase.CallOption) error
}

// Client calls the package RPCs. client is called per request, so each call
// carries the current access token. Callers wrap calls in
// auth.Service.DoWithAuthRetry.
type Client struct {
	client func() RPC
}

// NewClient returns a Client.
func NewClient(client func() RPC) *Client { return &Client{client: client} }

// FetchSettings calls agent_get_package_settings. changed is false when the
// server's settings still have knownVersion.
func (c *Client) FetchSettings(ctx context.Context, knownVersion string) (s Settings, changed bool, err error) {
	params := map[string]any{"p_known_version": nil}
	if knownVersion != "" {
		params["p_known_version"] = knownVersion
	}
	var raw []byte
	if err := c.client().RPC(ctx, rpcGetSettings, params, &raw); err != nil {
		return Settings{}, false, err
	}
	return decodeSettings(raw)
}

func decodeSettings(raw []byte) (Settings, bool, error) {
	var resp struct {
		Changed  bool      `json:"changed"`
		Settings *Settings `json:"settings"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &resp); err != nil {
		return Settings{}, false, fmt.Errorf("%s: decode response: %w", rpcGetSettings, err)
	}
	if !resp.Changed {
		return Settings{}, false, nil
	}
	if resp.Settings == nil || resp.Settings.Version == "" {
		return Settings{}, false, fmt.Errorf("%s: changed response without settings", rpcGetSettings)
	}
	return *resp.Settings, true, nil
}

// Upload is one agent_enqueue_packages call: a part of a full snapshot, or a
// delta.
type Upload struct {
	Snapshot    string    `json:"snapshot"`
	SnapshotID  string    `json:"snapshot_id,omitempty"`
	Part        int       `json:"part,omitempty"`
	Parts       int       `json:"parts,omitempty"`
	CollectedAt string    `json:"collected_at"`
	Packages    []Package `json:"packages"`
}

// Enqueue sends one upload, with the agent-enqueue retry policy (transient
// errors are retried until ctx ends; a rejected payload is logged and
// dropped).
func (c *Client) Enqueue(ctx context.Context, u Upload) error {
	params := map[string]any{"payload": u}
	return rpcutil.WithEnqueueRetry(ctx, func(ctx context.Context) error {
		var raw []byte
		return c.client().RPC(ctx, rpcEnqueue, params, &raw)
	})
}
