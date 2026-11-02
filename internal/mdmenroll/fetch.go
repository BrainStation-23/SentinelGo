package mdmenroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"sentinelgo/internal/supabase"
)

// rpcEnrollmentProfile returns this agent's single-use enrollment profile
// (contract v1, Compliance-OS#538), as {"profile_base64": "..."}.
const rpcEnrollmentProfile = "agent_get_mdm_enrollment_profile"

// maxProfileBytes bounds a profile; a signed enrollment profile is a few KB.
const maxProfileBytes = 1 << 20

// Retrier runs fn, recovering the session once on a 401
// (auth.Service.DoWithAuthRetry bound to the config).
type Retrier func(ctx context.Context, fn func() error) error

// ProfileFetcher returns a Deps.FetchProfile that calls the backend through
// client, with the device id header like the other agent RPCs.
func ProfileFetcher(client func() *supabase.Client, deviceID string, retry Retrier) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		var resp struct {
			ProfileBase64 string `json:"profile_base64"`
		}
		call := func() error {
			return client().RPC(ctx, rpcEnrollmentProfile, map[string]any{}, &resp, supabase.WithHeader("X-Device-ID", deviceID))
		}
		var err error
		if retry != nil {
			err = retry(ctx, call)
		} else {
			err = call()
		}
		if supabase.IsNotFound(err) {
			return nil, errors.New("the server doesn't offer MDM enrollment yet")
		}
		if err != nil {
			return nil, err
		}
		return decodeProfile(resp.ProfileBase64)
	}
}

// decodeProfile checks that what the server sent is a configuration profile:
// a signed one (CMS, DER: starts with a SEQUENCE) or an unsigned XML plist.
func decodeProfile(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return nil, errors.New("the server sent no enrollment profile")
	}
	if base64.StdEncoding.DecodedLen(len(b64)) > maxProfileBytes {
		return nil, fmt.Errorf("the enrollment profile is over %d bytes", maxProfileBytes)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("the enrollment profile isn't valid base64: %w", err)
	}
	head := bytes.TrimSpace(data[:min(len(data), 64)])
	signed := len(data) > 0 && data[0] == 0x30
	plist := bytes.HasPrefix(head, []byte("<?xml")) || bytes.HasPrefix(head, []byte("<plist"))
	if !signed && !plist {
		return nil, errors.New("the server sent something that isn't a configuration profile")
	}
	return data, nil
}
