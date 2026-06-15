package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/httpx"
)

// agentLoginEndpoint is the public Supabase edge function that exchanges the
// agent's long-lived credentials for a fresh Supabase session. It requires no
// JWT (the agent has none yet when it calls this); the anon apikey gates the
// edge gateway.
const agentLoginEndpoint = "/functions/v1/agent-login"

// loginTimeout bounds a single agent-login HTTP request.
const loginTimeout = 60 * time.Second

// ErrLoginRejected indicates the backend rejected the agent's credentials
// (HTTP 401/403) — i.e. the agent_id/agent_secret is invalid or has been
// withdrawn. This is unrecoverable without re-provisioning, so callers treat it
// differently from a transient (network/5xx) failure they can retry.
var ErrLoginRejected = errors.New("agent-login rejected credentials")

// loginRequest is the agent-login request body.
type loginRequest struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
}

// loginResponse is the agent-login success body. Supabase returns a flat token
// pair plus the access token's lifetime in seconds.
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Login exchanges cfg.AgentID + cfg.AgentSecret for a brand-new Supabase
// session via the agent-login edge function, then updates the in-memory config,
// the active session, and persists the rotated tokens to disk.
//
// This is the agent's bootstrap and ultimate fallback: it is called at startup
// and whenever a refresh can no longer recover the session. On HTTP 401/403 it
// returns ErrLoginRejected (wrapped) so the caller can stop retrying and surface
// a "needs re-provisioning" state.
func (s *Service) Login(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("login: config is nil")
	}
	if cfg.AgentID == "" || cfg.AgentSecret == "" {
		return fmt.Errorf("login: agent_id and agent_secret must be configured")
	}
	if s.baseURL == "" {
		return fmt.Errorf("login: base URL not configured")
	}

	reqBody, err := json.Marshal(loginRequest{AgentID: cfg.AgentID, AgentSecret: cfg.AgentSecret})
	if err != nil {
		return fmt.Errorf("login: marshal request: %w", err)
	}

	url := s.baseURL + agentLoginEndpoint
	client := httpx.NewClient(loginTimeout)

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		log.Printf("Auth: agent-login attempt %d/%d", attempt+1, maxRetries)

		resp, rejected, retryable, err := s.doLoginRequest(ctx, client, url, reqBody)
		if rejected {
			// Credentials are bad — retrying with the same secret is pointless.
			return fmt.Errorf("%w: %v", ErrLoginRejected, err)
		}
		if err != nil {
			lastErr = err
			if !retryable {
				// Terminal-but-transient (e.g. HTTP 429 rate limit). Retrying in a
				// tight loop would only log more failed attempts server-side and
				// extend the lockout, so stop now and let the circuit breaker back
				// off — its reset window matches the server's rate-limit window.
				return fmt.Errorf("agent-login not retryable: %w", err)
			}
			log.Printf("Auth: agent-login attempt %d failed: %v", attempt+1, err)
			continue
		}

		if resp.AccessToken == "" {
			lastErr = fmt.Errorf("agent-login returned empty access token")
			continue
		}

		cfg.SetTokens(resp.AccessToken, resp.RefreshToken)
		if err := s.SetSession(resp.AccessToken, resp.RefreshToken); err != nil {
			log.Printf("Auth: warning – failed to update session after login: %v", err)
		}
		if err := saveTokensWithRetry(cfg); err != nil {
			emergencylog.Record("auth", "agent-login succeeded but failed to persist tokens (disk/backend desync risk): %v", err)
			return fmt.Errorf("agent-login succeeded but failed to persist tokens: %w", err)
		}

		log.Printf("Auth: agent-login successful (token length: %d, expires_in: %ds)", len(resp.AccessToken), resp.ExpiresIn)
		return nil
	}

	return fmt.Errorf("agent-login failed after %d attempts: %w", maxRetries, lastErr)
}

// doLoginRequest performs one agent-login HTTP round-trip and classifies the
// outcome for the retry loop:
//   - rejected=true   → HTTP 401/403, bad credentials; caller must NOT retry and
//     should surface ErrLoginRejected (needs re-provisioning).
//   - retryable=true  → transient (network / 5xx); caller may retry with backoff.
//   - retryable=false with a non-nil err → terminal but not a credential
//     rejection (e.g. HTTP 429 rate limit): stop retrying, let the breaker back
//     off rather than piling up server-side failed-attempt records.
func (s *Service) doLoginRequest(ctx context.Context, client *http.Client, url string, body []byte) (resp *loginResponse, rejected, retryable bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, false, false, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Public endpoint: no Authorization bearer. The anon apikey gates the edge
	// gateway (Supabase rejects function calls without it).
	if s.apiKey != "" {
		httpReq.Header.Set("apikey", s.apiKey)
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, false, true, fmt.Errorf("http request: %w", err)
	}
	defer func() {
		if cerr := httpResp.Body.Close(); cerr != nil {
			log.Printf("Auth: failed to close agent-login response body: %v", cerr)
		}
	}()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, false, true, fmt.Errorf("read response: %w", err)
	}

	switch {
	case httpResp.StatusCode == http.StatusUnauthorized || httpResp.StatusCode == http.StatusForbidden:
		return nil, true, false, fmt.Errorf("status %d: %s", httpResp.StatusCode, string(respBody))
	case httpResp.StatusCode == http.StatusTooManyRequests:
		return nil, false, false, fmt.Errorf("rate limited: status %d: %s", httpResp.StatusCode, string(respBody))
	case httpResp.StatusCode != http.StatusOK:
		return nil, false, true, fmt.Errorf("status %d: %s", httpResp.StatusCode, string(respBody))
	}

	var lr loginResponse
	if err := json.Unmarshal(respBody, &lr); err != nil {
		return nil, false, true, fmt.Errorf("unmarshal response: %w", err)
	}
	return &lr, false, false, nil
}
