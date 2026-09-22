package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/emergencylog"
	"sentinelgo/internal/resilience"

	supabase "github.com/supabase-community/supabase-go"
)

// maxRetries bounds how many times a single refresh or agent-login attempt is
// retried on a transient (network/5xx) failure. It is a var rather than a const
// so tests can lower it to keep breaker/recovery tests fast and deterministic.
var maxRetries = 3

// authBreakerMaxFailures / authBreakerResetTimeout tune the circuit breaker that
// gates session recovery. After this many consecutive recovery failures the
// breaker opens and rejects further attempts for the reset window, throttling a
// permanently-failing agent from hammering the auth endpoints every tick.
const (
	authBreakerMaxFailures  = 5
	authBreakerResetTimeout = 5 * time.Minute
)

// Service manages Supabase authentication state and is the single authority for
// keeping the session valid.
//
// Token refresh is serialised: only one refresh is in-flight at a time.
// Additional goroutines that arrive while a refresh is running wait on an
// internal channel and return without issuing a duplicate network request.
// Recover (refresh-then-login) is serialised the same way via its own channel,
// so concurrent callers reacting to a 401 cannot trigger a login storm.
type Service struct {
	baseURL string
	apiKey  string // Supabase anon key, sent as the apikey header to public endpoints
	client  *supabase.Client

	refreshMu sync.Mutex
	// refreshCh is non-nil while a refresh is in progress.
	// Latecomers wait on this channel rather than starting a second refresh.
	refreshCh chan struct{}
	// refreshErr holds the outcome of the most recent refresh, published by the
	// leader before it closes refreshCh so waiters return the real result rather
	// than a false success.
	refreshErr error

	// recoverMu / recoverCh / recoverErr provide the same single-flight guard for
	// Recover as refresh* does for RefreshToken.
	recoverMu  sync.Mutex
	recoverCh  chan struct{}
	recoverErr error

	// breaker gates Recover so repeated failures back off instead of hammering.
	breaker *resilience.CircuitBreaker
	// needsReprovision is set once agent-login rejects the stored credentials.
	// While set, the session is unrecoverable without operator action and
	// reporting tasks pause rather than spin on guaranteed-401 requests.
	needsReprovision atomic.Bool
}

// NewService creates a new authentication service. apiKey is the Supabase anon
// key used to initialise the client and to gate calls to the public agent-login
// endpoint.
func NewService(baseURL, apiKey string) *Service {
	s := &Service{
		baseURL: baseURL,
		apiKey:  apiKey,
		breaker: resilience.NewCircuitBreaker("auth-service", authBreakerMaxFailures, authBreakerResetTimeout),
	}
	if client, err := supabase.NewClient(baseURL, apiKey, nil); err == nil {
		s.client = client
	}
	return s
}

// InitSession configures the Supabase client using tokens already stored in
// cfg. No network call is made. Call this once at startup instead of Login.
func (s *Service) InitSession(cfg *config.Config) error {
	if cfg.AccessToken == "" {
		return fmt.Errorf("no access token in config – agent must be registered before first run")
	}
	if err := s.SetSession(cfg.AccessToken, cfg.RefreshToken); err != nil {
		return err
	}
	log.Printf("Auth: session initialised from stored tokens")
	return nil
}

// SetSession swaps the internal Supabase client for one authenticated with
// accessToken. Equivalent to supabase.auth.setSession() in the JS SDK.
func (s *Service) SetSession(accessToken, refreshToken string) error {
	if s.baseURL == "" {
		return fmt.Errorf("base URL not configured")
	}
	// The access token serves as both the apikey and the Authorization bearer.
	client, err := supabase.NewClient(s.baseURL, accessToken, &supabase.ClientOptions{
		Headers: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	})
	if err != nil {
		return fmt.Errorf("create client with access token: %w", err)
	}
	// Keep the gotrue Auth client in sync with the access token.
	client.Auth = client.Auth.WithToken(accessToken)
	s.client = client
	return nil
}

// RefreshToken exchanges the stored refresh token for a new access/refresh pair,
// updates cfg in-memory, and persists the updated tokens to disk.
//
// Concurrency-safe: the first caller performs the refresh; any goroutine that
// arrives while a refresh is running blocks until it finishes and then returns
// (cfg has already been updated by the winning goroutine).
func (s *Service) RefreshToken(ctx context.Context, cfg *config.Config) error {
	s.refreshMu.Lock()

	if s.refreshCh != nil {
		// A refresh is already running – wait for it to finish and return ITS
		// outcome. Returning nil unconditionally (the previous behaviour) made
		// waiters believe a failed refresh had succeeded, so they retried with
		// the same expired token.
		ch := s.refreshCh
		s.refreshMu.Unlock()
		log.Printf("Auth: waiting for in-progress token refresh")
		select {
		case <-ch:
			s.refreshMu.Lock()
			err := s.refreshErr
			s.refreshMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// This goroutine leads the refresh cycle.
	s.refreshCh = make(chan struct{})
	s.refreshMu.Unlock()

	err := s.doRefresh(ctx, cfg)

	// Publish the result, then release waiters.
	s.refreshMu.Lock()
	s.refreshErr = err
	close(s.refreshCh)
	s.refreshCh = nil
	s.refreshMu.Unlock()

	return err
}

// doRefresh performs the actual network token exchange. Must only be called by
// the goroutine that created the current refreshCh.
func (s *Service) doRefresh(ctx context.Context, cfg *config.Config) error {
	if cfg.RefreshToken == "" {
		return fmt.Errorf("no refresh token available in config")
	}
	if s.client == nil {
		return fmt.Errorf("supabase client not initialised")
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		log.Printf("Auth: token refresh attempt %d/%d", attempt+1, maxRetries)

		// RefreshToken on the supabase client returns types.Session directly
		// and also calls UpdateAuthSession internally to keep the client in sync.
		session, err := s.client.RefreshToken(cfg.RefreshToken)
		if err != nil {
			lastErr = err
			log.Printf("Auth: refresh attempt %d failed: %v", attempt+1, err)

			// Only re-send the refresh token when the failure proves it was
			// never delivered. Supabase rotates on every successful exchange,
			// so after an ambiguous failure (timeout, reset, EOF) the token we
			// hold may already be spent — re-sending it cannot succeed, and
			// under refresh-token reuse detection it reads as a replay and
			// revokes the session family. Give up instead and let the caller
			// fall back to agent-login, which is the designed bootstrap.
			if !isRefreshTokenUnused(err) {
				return fmt.Errorf("token refresh failed, not retrying "+
					"(refresh token may already be rotated server-side): %w", err)
			}
			continue
		}

		// Update in-memory config first so concurrent waiters see the new token.
		// Go through SetTokens: it takes config.tokenMu, which every reader of
		// GetAccessToken/GetRefreshToken holds. Assigning the fields directly
		// races the heartbeat, software-sync and upload goroutines.
		cfg.SetTokens(session.AccessToken, session.RefreshToken)

		// Swap the internal client to use the new access token.
		if err := s.SetSession(session.AccessToken, session.RefreshToken); err != nil {
			log.Printf("Auth: warning – failed to update session after refresh: %v", err)
		}

		// Persist to disk so the rotated tokens survive a restart. Supabase
		// rotates the refresh token on every refresh, so if we fail to persist
		// the new pair and the process later restarts, disk holds a refresh token
		// the backend has already revoked — leaving the agent permanently unable
		// to authenticate. Treat a persistent save failure as a refresh failure
		// (after retries) rather than silently swallowing it.
		if err := saveTokensWithRetry(cfg); err != nil {
			emergencylog.Record("auth", "token refreshed but failed to persist rotated tokens (disk/backend desync risk): %v", err)
			return fmt.Errorf("token refreshed but failed to persist rotated tokens: %w", err)
		}

		log.Printf("Auth: token refresh successful (token length: %d)", len(session.AccessToken))
		return nil
	}

	return fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// Recover restores a usable session: it first tries a token refresh, and if that
// fails falls back to a full agent-login with the stored agent_secret. The whole
// sequence is single-flight (so concurrent 401 reactions don't launch parallel
// logins) and gated by a circuit breaker (so a permanently-failing recovery
// backs off to the breaker's reset cadence instead of retrying every tick).
//
// On agent-login rejection it marks the agent as needing re-provisioning; on any
// success it clears that flag.
func (s *Service) Recover(ctx context.Context, cfg *config.Config) error {
	s.recoverMu.Lock()
	if s.recoverCh != nil {
		ch := s.recoverCh
		s.recoverMu.Unlock()
		log.Printf("Auth: waiting for in-progress session recovery")
		select {
		case <-ch:
			s.recoverMu.Lock()
			err := s.recoverErr
			s.recoverMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.recoverCh = make(chan struct{})
	s.recoverMu.Unlock()

	err := s.breaker.Execute(ctx, func() error {
		return s.doRecover(ctx, cfg)
	})

	s.recoverMu.Lock()
	s.recoverErr = err
	close(s.recoverCh)
	s.recoverCh = nil
	s.recoverMu.Unlock()
	return err
}

// doRecover is the leader's recovery sequence: refresh, then agent-login. It is
// only ever called by the single Recover leader, so calling the internal
// doRefresh/Login directly here cannot race a second recovery.
func (s *Service) doRecover(ctx context.Context, cfg *config.Config) error {
	if cfg.RefreshToken != "" {
		if err := s.doRefresh(ctx, cfg); err == nil {
			s.needsReprovision.Store(false)
			return nil
		} else {
			log.Printf("Auth: refresh failed during recovery (%v); falling back to agent-login", err)
		}
	}

	if err := s.Login(ctx, cfg); err != nil {
		if errors.Is(err, ErrLoginRejected) {
			if s.needsReprovision.CompareAndSwap(false, true) {
				log.Printf("Auth: CRITICAL — agent-login rejected the stored agent_secret. " +
					"The agent cannot authenticate and needs re-provisioning; reporting is paused " +
					"until valid credentials are restored.")
				emergencylog.Record("auth", "agent-login rejected stored credentials; agent needs re-provisioning, reporting paused")
			}
		}
		return err
	}

	s.needsReprovision.Store(false)
	return nil
}

// DoWithAuthRetry runs fn; if fn fails with a 401-style error it recovers the
// session (refresh→login) and retries fn exactly once. A 403 (authenticated but
// forbidden) and all other errors are returned untouched — recovering the token
// would not help. This is the single 401-handling pattern shared by every
// reporting path.
func (s *Service) DoWithAuthRetry(ctx context.Context, cfg *config.Config, fn func() error) error {
	err := fn()
	if err == nil || !IsUnauthorized(err) {
		return err
	}

	log.Printf("Auth: request failed with 401; attempting session recovery before retry")
	if rerr := s.Recover(ctx, cfg); rerr != nil {
		log.Printf("Auth: recovery after 401 failed: %v", rerr)
		return err // surface the original 401, not the recovery error
	}
	return fn()
}

// Healthy reports whether the agent currently holds (or can recover) a valid
// session. It is false while the recovery breaker is open or the credentials
// have been rejected — reporting tasks use this to pause instead of hammering.
func (s *Service) Healthy() bool {
	return !s.needsReprovision.Load() && s.breaker.GetState() != resilience.StateOpen
}

// NeedsReprovision reports whether agent-login has rejected the stored
// credentials, meaning the agent requires operator re-provisioning.
func (s *Service) NeedsReprovision() bool {
	return s.needsReprovision.Load()
}

// AuthStatus is a point-in-time view of authentication health for status output.
type AuthStatus struct {
	Healthy          bool                           `json:"healthy"`
	NeedsReprovision bool                           `json:"needs_reprovision"`
	CircuitBreaker   resilience.CircuitBreakerStats `json:"circuit_breaker"`
}

// Status returns a snapshot of authentication health.
func (s *Service) Status() AuthStatus {
	return AuthStatus{
		Healthy:          s.Healthy(),
		NeedsReprovision: s.needsReprovision.Load(),
		CircuitBreaker:   s.breaker.GetStats(),
	}
}

// saveTokensWithRetry persists the config with a few bounded retries to ride out
// a transient disk/IO error. Returns the last error if all attempts fail.
func saveTokensWithRetry(cfg *config.Config) error {
	const saveAttempts = 3
	var err error
	for attempt := 0; attempt < saveAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
		if err = cfg.SaveAtomic(); err == nil {
			return nil
		}
		log.Printf("Auth: persist refreshed tokens attempt %d/%d failed: %v", attempt+1, saveAttempts, err)
	}
	return err
}
