package auth

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/config"

	supabase "github.com/supabase-community/supabase-go"
)

const maxRetries = 3

// Service manages Supabase authentication state.
//
// Token refresh is serialised: only one refresh is in-flight at a time.
// Additional goroutines that arrive while a refresh is running wait on an
// internal channel and return without issuing a duplicate network request.
type Service struct {
	baseURL string
	client  *supabase.Client

	refreshMu sync.Mutex
	// refreshCh is non-nil while a refresh is in progress.
	// Latecomers wait on this channel rather than starting a second refresh.
	refreshCh chan struct{}
}

// NewService creates a new authentication service. apiKey is used for the
// Supabase client initialisation; callers should pass cfg.AccessToken.
func NewService(baseURL, apiKey string) *Service {
	client, err := supabase.NewClient(baseURL, apiKey, nil)
	if err != nil {
		return &Service{baseURL: baseURL}
	}
	return &Service{
		client:  client,
		baseURL: baseURL,
	}
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
		// A refresh is already running – wait for it to finish.
		ch := s.refreshCh
		s.refreshMu.Unlock()
		log.Printf("Auth: waiting for in-progress token refresh")
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// This goroutine leads the refresh cycle.
	s.refreshCh = make(chan struct{})
	s.refreshMu.Unlock()

	defer func() {
		s.refreshMu.Lock()
		close(s.refreshCh)
		s.refreshCh = nil
		s.refreshMu.Unlock()
	}()

	return s.doRefresh(ctx, cfg)
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
			continue
		}

		// Update in-memory config first so concurrent waiters see the new token.
		cfg.AccessToken = session.AccessToken
		cfg.RefreshToken = session.RefreshToken

		// Swap the internal client to use the new access token.
		if err := s.SetSession(session.AccessToken, session.RefreshToken); err != nil {
			log.Printf("Auth: warning – failed to update session after refresh: %v", err)
		}

		// Persist to disk atomically so the tokens survive a process restart.
		if err := cfg.SaveAtomic(); err != nil {
			log.Printf("Auth: warning – failed to persist refreshed tokens: %v", err)
		} else {
			log.Printf("Auth: token refresh successful (token length: %d)", len(session.AccessToken))
		}

		return nil
	}

	return fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}
