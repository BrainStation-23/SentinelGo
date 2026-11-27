package mdmenroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sentinelgo/internal/httpx"
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

// signedProfileTimeout bounds the download of the signed profile from the
// MDM host; past it the unsigned copy is used.
const signedProfileTimeout = 30 * time.Second

// ProfileFetcher returns a Deps.FetchProfile that calls the backend through
// client. The server takes the device from the token's agent.
//
// A server with Compliance-OS#1164 also returns profile_url and a one-time
// profile_token: the same profile signed (CMS) on the MDM host, so macOS
// names who it is from (#569). The agent prefers it and falls back to the
// unsigned profile_base64 on any failure; the server keeps that copy usable
// until the signed one is handed out.
func ProfileFetcher(client func() *supabase.Client, retry Retrier) func(ctx context.Context) ([]byte, error) {
	return profileFetcher(client, retry, httpx.NewClient(signedProfileTimeout))
}

func profileFetcher(client func() *supabase.Client, retry Retrier, web *http.Client) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		var resp struct {
			ProfileBase64 string `json:"profile_base64"`
			ProfileURL    string `json:"profile_url"`
			ProfileToken  string `json:"profile_token"`
		}
		call := func() error {
			return client().RPC(ctx, rpcEnrollmentProfile, map[string]any{}, &resp)
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
		if resp.ProfileURL != "" && resp.ProfileToken != "" {
			signed, serr := fetchSignedProfile(ctx, web, resp.ProfileURL, resp.ProfileToken)
			if serr == nil {
				return signed, nil
			}
			// never the token: it is a one-time credential
			log.Printf("mdm-enroll: using the unsigned enrollment profile: %v", serr)
		}
		return decodeProfile(resp.ProfileBase64)
	}
}

// fetchSignedProfile trades the one-time token for the signed profile:
// POST {"token": …} to the https URL the server gave, answer 200 with the
// CMS-signed .mobileconfig. Anything else is an error, and the caller uses
// the unsigned copy. The token is used once, so this isn't retried.
func fetchSignedProfile(ctx context.Context, web *http.Client, rawURL, token string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the signed profile's URL isn't https")
	}
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/x-apple-aspen-config")
	res, err := web.Do(req)
	if err != nil {
		// a url.Error carries the URL, not the token (it is in the body)
		return nil, fmt.Errorf("downloading the signed profile: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("the MDM host answered %d for the signed profile", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the signed profile: %w", err)
	}
	if len(data) > maxProfileBytes {
		return nil, fmt.Errorf("the signed profile is over %d bytes", maxProfileBytes)
	}
	if len(data) == 0 || data[0] != 0x30 {
		return nil, errors.New("the MDM host's answer isn't a signed profile")
	}
	return data, nil
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

// rpcWindowsEnrollment returns what RegisterDeviceWithManagement needs for
// this agent's device (contract v1, Compliance-OS#551).
const rpcWindowsEnrollment = "agent_get_windows_enrollment"

// WindowsEnrollment is the backend's answer: a single-use token, bound to
// this agent, that the enrollment server accepts as the security token.
type WindowsEnrollment struct {
	DiscoveryURL string `json:"discovery_url"`
	UPN          string `json:"upn"`
	AccessToken  string `json:"access_token"`
}

// WindowsEnrollmentFetcher returns a Deps.FetchWindowsEnrollment. The token
// is never logged.
func WindowsEnrollmentFetcher(client func() *supabase.Client, retry Retrier) func(ctx context.Context) (WindowsEnrollment, error) {
	return func(ctx context.Context) (WindowsEnrollment, error) {
		var resp WindowsEnrollment
		call := func() error {
			return client().RPC(ctx, rpcWindowsEnrollment, map[string]any{}, &resp)
		}
		var err error
		if retry != nil {
			err = retry(ctx, call)
		} else {
			err = call()
		}
		if supabase.IsNotFound(err) {
			return WindowsEnrollment{}, errors.New("the server doesn't offer Windows MDM enrollment yet")
		}
		if err != nil {
			return WindowsEnrollment{}, err
		}
		u, perr := url.Parse(resp.DiscoveryURL)
		if perr != nil || u.Scheme != "https" || u.Host == "" {
			return WindowsEnrollment{}, errors.New("the server's discovery URL isn't https")
		}
		if strings.TrimSpace(resp.UPN) == "" || strings.TrimSpace(resp.AccessToken) == "" {
			return WindowsEnrollment{}, errors.New("the server's answer lacks the UPN or access token")
		}
		return resp, nil
	}
}
