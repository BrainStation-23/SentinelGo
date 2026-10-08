package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/supabase"
)

// agentLoginFunction is the public Supabase edge function that exchanges the
// agent's long-lived credentials for a fresh Supabase session. It requires no
// JWT (the agent has none yet when it calls this); the anon apikey gates the
// edge gateway.
const agentLoginFunction = "agent-login"

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
// session via the agent-login edge function, then updates the in-memory config
// and persists the rotated tokens to disk.
//
// This is the agent's bootstrap and ultimate fallback: it is called at startup
// and whenever a refresh can no longer recover the session. On HTTP 401/403 it
// returns ErrLoginRejected (wrapped) so the caller can stop retrying and surface
// a "needs re-provisioning" state.
func (s *Service) Login(ctx context.Context, cfg *config.Config) error {
	return s.login(ctx, cfg, true)
}

// LoginInMemory is Login without persisting the new tokens: cfg is updated in
// memory only. The CLI uses it so a one-off command never writes tokens the
// running service also owns (with refresh rotation live, persisting from a
// second process would race the service's own token family).
func (s *Service) LoginInMemory(ctx context.Context, cfg *config.Config) error {
	return s.login(ctx, cfg, false)
}

func (s *Service) login(ctx context.Context, cfg *config.Config, persist bool) error {
	if cfg == nil {
		return fmt.Errorf("login: config is nil")
	}
	if cfg.AgentID == "" || cfg.AgentSecret == "" {
		return fmt.Errorf("login: agent_id and agent_secret must be configured")
	}
	if s.baseURL == "" {
		return fmt.Errorf("login: base URL not configured")
	}

	req := loginRequest{AgentID: cfg.AgentID, AgentSecret: cfg.AgentSecret}

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

		resp, rejected, retryable, err := s.doLoginRequest(ctx, req)
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
		if persist {
			if err := saveTokensWithRetry(cfg); err != nil {
				emergencylog.Record("auth", "agent-login succeeded but failed to persist tokens (disk/backend desync risk): %v", err)
				return fmt.Errorf("agent-login succeeded but failed to persist tokens: %w", err)
			}
		}

		log.Printf("Auth: agent-login successful (token length: %d, expires_in: %ds)", len(resp.AccessToken), resp.ExpiresIn)
		return nil
	}

	return fmt.Errorf("agent-login failed after %d attempts: %w", maxRetries, lastErr)
}

// doLoginRequest performs one agent-login round-trip and classifies the
// outcome for the retry loop:
//   - rejected=true   → HTTP 401/403, bad credentials; caller must NOT retry and
//     should surface ErrLoginRejected (needs re-provisioning).
//   - retryable=true  → transient (network / 5xx / bad response); caller may
//     retry with backoff.
//   - retryable=false with a non-nil err → terminal but not a credential
//     rejection (HTTP 429 rate limit): stop retrying, let the breaker back off
//     rather than piling up server-side failed-attempt records.
func (s *Service) doLoginRequest(ctx context.Context, req loginRequest) (resp *loginResponse, rejected, retryable bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	var lr loginResponse
	err = s.sb.InvokeFunction(ctx, agentLoginFunction, req, &lr)
	if err == nil {
		return &lr, false, false, nil
	}
	switch supabase.StatusCode(err) {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, true, false, err
	case http.StatusTooManyRequests:
		return nil, false, false, fmt.Errorf("rate limited: %w", err)
	default:
		return nil, false, true, err
	}
}
