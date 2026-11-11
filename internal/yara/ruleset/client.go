package ruleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
)

// Bucket is the private Storage bucket of rule sources (Compliance-OS
// docs/yara.md); an agent may read exactly the storage_paths its bundle
// lists, through the authenticated object path.
const Bucket = "yara-rules"

// Errors a Fetcher or Downloader returns.
var (
	// ErrStatusRejected: the server refused the status (22023). The poll is
	// repeated without it.
	ErrStatusRejected = errors.New("YARA status rejected by the server")
	ErrNotFound       = errors.New("YARA rule source not found in Storage")
	ErrTooLarge       = errors.New("YARA rule source larger than the bundle says")
)

// Supabase is what Client needs from supabase.Client (an interface so tests
// can fake the server).
type Supabase interface {
	RPC(ctx context.Context, fn string, params, out any, opts ...supabase.CallOption) error
	Download(ctx context.Context, bucket, objectPath string, authenticatedPrefix bool, w io.Writer, limit int64) (int64, error)
}

// Client calls agent_get_yara_ruleset and downloads rule sources, both
// through internal/supabase. client is called per request, so each call
// carries the current access token; callers wrap calls in DoWithAuthRetry.
type Client struct{ client func() Supabase }

// NewClient returns a Client.
func NewClient(client func() Supabase) *Client { return &Client{client: client} }

// FetchResult is the poll's answer: changed, with the bundle JSON, or not.
type FetchResult struct {
	Changed bool
	Raw     []byte
}

// FetchRuleset calls agent_get_yara_ruleset. status nil sends p_status null.
func (c *Client) FetchRuleset(ctx context.Context, knownVersion string, status *yara.Status) (FetchResult, error) {
	params := struct {
		KnownVersion string          `json:"p_known_version"`
		Status       json.RawMessage `json:"p_status"`
	}{KnownVersion: knownVersion, Status: json.RawMessage("null")}
	if status != nil {
		data, err := status.Encode()
		if err != nil {
			return FetchResult{}, err
		}
		params.Status = data
	}
	var raw []byte
	err := c.client().RPC(ctx, yara.RPCGetRuleset, params, &raw)
	if err != nil {
		if e, ok := supabase.AsAPIError(err); ok && e.Code == yara.SQLStateInvalid && status != nil {
			return FetchResult{}, fmt.Errorf("%w: %w", ErrStatusRejected, err)
		}
		return FetchResult{}, err
	}
	var resp struct {
		Changed bool            `json:"changed"`
		Bundle  json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &resp); err != nil {
		return FetchResult{}, fmt.Errorf("%s: decode response: %w", yara.RPCGetRuleset, err)
	}
	if !resp.Changed {
		return FetchResult{}, nil
	}
	if len(resp.Bundle) == 0 || string(resp.Bundle) == "null" {
		return FetchResult{}, fmt.Errorf("%s: changed without a bundle", yara.RPCGetRuleset)
	}
	return FetchResult{Changed: true, Raw: resp.Bundle}, nil
}

// DownloadRuleset streams one rule source into w, failing past limit bytes.
func (c *Client) DownloadRuleset(ctx context.Context, storagePath string, w io.Writer, limit int64) error {
	_, err := c.client().Download(ctx, Bucket, storagePath, true, w, limit)
	switch {
	case err == nil:
		return nil
	case supabase.IsNotFound(err):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, supabase.ErrTooLarge):
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	return err
}
