// Package dlp wraps the DLP RPCs (contract: sentinel-ops docs/dlp.md). All
// calls go through internal/supabase; callers wrap them in
// auth.Service.DoWithAuthRetry so a 401 recovers the session once.
package dlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"sentinelgo/internal/dlp"
	"sentinelgo/internal/supabase"
)

const (
	rpcGetPolicy    = "agent_get_dlp_policy"
	headerXDeviceID = "X-Device-ID"

	// codeInvalidParameter is PostgREST's code when the function rejects a
	// parameter; agent_get_dlp_policy uses it for a malformed or oversized
	// status (do not retry the same status).
	codeInvalidParameter = "22023"
)

// Service calls the DLP RPCs. client is called per request, so it always
// carries the current access token.
type Service struct {
	client   func() *supabase.Client
	deviceID string
}

// New returns a Service.
func New(client func() *supabase.Client, deviceID string) *Service {
	return &Service{client: client, deviceID: deviceID}
}

type getPolicyParams struct {
	KnownVersion *string     `json:"p_known_version"`
	Status       *dlp.Status `json:"p_status,omitempty"`
}

// FetchPolicy calls agent_get_dlp_policy. It implements dlp.Fetcher.
func (s *Service) FetchPolicy(ctx context.Context, knownVersion string, status *dlp.Status) (dlp.FetchResult, error) {
	params := getPolicyParams{Status: status}
	if knownVersion != "" {
		params.KnownVersion = &knownVersion
	}
	var raw []byte
	err := s.client().RPC(ctx, rpcGetPolicy, params, &raw, supabase.WithHeader(headerXDeviceID, s.deviceID))
	if err != nil {
		if e, ok := supabase.AsAPIError(err); ok && e.Code == codeInvalidParameter && status != nil {
			return dlp.FetchResult{}, fmt.Errorf("%w: %w", dlp.ErrStatusRejected, err)
		}
		return dlp.FetchResult{}, err
	}
	return decodePolicyResponse(raw)
}

// decodePolicyResponse tells {"unchanged":true,...} from a bundle.
func decodePolicyResponse(raw []byte) (dlp.FetchResult, error) {
	raw = bytes.TrimSpace(raw)
	var probe struct {
		Unchanged bool `json:"unchanged"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return dlp.FetchResult{}, fmt.Errorf("%s: decode response: %w", rpcGetPolicy, err)
	}
	if probe.Unchanged {
		return dlp.FetchResult{Unchanged: true}, nil
	}
	return dlp.FetchResult{Raw: raw}, nil
}
