package auth

import (
	"context"
	"fmt"
	"log"
	"sync"

	"sentinelgo/internal/config"
)

// SessionManager wraps Service and provides a higher-level API for managing
// the authentication lifecycle without calling the login API at runtime.
//
// It holds a pointer to the same *config.Config used by the rest of the
// program, so token updates are immediately visible everywhere.
type SessionManager struct {
	mu     sync.RWMutex
	cfg    *config.Config
	client *Service
}

// NewSessionManager creates a SessionManager backed by an existing Service and
// the program's live Config pointer.
func NewSessionManager(cfg *config.Config, client *Service) *SessionManager {
	return &SessionManager{
		cfg:    cfg,
		client: client,
	}
}

// InitializeSession sets up authentication using tokens already stored in cfg.
// It NEVER calls the login API. Returns an error when cfg holds no access
// token – in that case the agent must be registered via a separate CLI command
// before the service can start.
func (sm *SessionManager) InitializeSession() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.cfg.AccessToken == "" {
		return fmt.Errorf("no access token in config – run the registration command first")
	}

	if err := sm.client.SetSession(sm.cfg.AccessToken, sm.cfg.RefreshToken); err != nil {
		return fmt.Errorf("set session: %w", err)
	}

	log.Printf("SessionManager: session initialised from stored tokens")
	return nil
}

// RefreshTokens requests a new access/refresh token pair using the stored
// refresh token. It delegates to Service.RefreshToken which serialises
// concurrent callers so only one network request is made per expiry event.
func (sm *SessionManager) RefreshTokens(ctx context.Context) error {
	sm.mu.RLock()
	cfg := sm.cfg
	sm.mu.RUnlock()

	if cfg == nil {
		return fmt.Errorf("session manager not initialised")
	}

	if err := sm.client.RefreshToken(ctx, cfg); err != nil {
		return fmt.Errorf("refresh tokens: %w", err)
	}

	log.Printf("SessionManager: tokens refreshed successfully")
	return nil
}

// IsAuthenticated reports whether the session holds a non-empty access token.
func (sm *SessionManager) IsAuthenticated() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.cfg != nil && sm.cfg.AccessToken != ""
}

// GetAccessToken returns the current access token.
func (sm *SessionManager) GetAccessToken() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.cfg != nil {
		return sm.cfg.AccessToken
	}
	return ""
}
