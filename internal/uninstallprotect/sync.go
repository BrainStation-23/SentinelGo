package uninstallprotect

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/supabase"
)

// RPCName is the agent RPC of the contract.
const RPCName = "agent_get_uninstall_protection"

// TickInterval is how often the sync task polls. A rotated token or a
// switched setting reaches the device within this time.
const TickInterval = 15 * time.Minute

// permanentBackoff is how long the sync waits after an answer a retry
// won't change: a revoked agent (42501), a caller that isn't an agent
// (P0002), or a server without the RPC.
const permanentBackoff = 6 * time.Hour

// RPC is the Supabase RPC call (supabase.Client.RPC); an interface so tests
// can fake the server.
type RPC interface {
	RPC(ctx context.Context, fn string, params, out any, opts ...supabase.CallOption) error
}

// Retrier runs fn, recovering the session once on a 401
// (auth.Service.DoWithAuthRetry).
type Retrier func(ctx context.Context, fn func() error) error

// Syncer keeps StateFileName in step with the server.
type Syncer struct {
	client func() RPC
	retry  Retrier
	path   string
	now    func() time.Time

	mu        sync.Mutex
	notBefore time.Time
}

// NewSyncer returns a Syncer that writes to path. client is called per
// request, so each call carries the current access token. retry may be nil.
func NewSyncer(client func() RPC, retry Retrier, path string) *Syncer {
	if retry == nil {
		retry = func(_ context.Context, fn func() error) error { return fn() }
	}
	return &Syncer{client: client, retry: retry, path: path, now: time.Now}
}

// Tick syncs unless a permanent error asked it to wait.
func (s *Syncer) Tick(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Before(s.notBefore) {
		return nil
	}
	err := s.sync(ctx)
	if err != nil && permanent(err) {
		s.notBefore = s.now().Add(permanentBackoff)
		log.Printf("Uninstall protection: sync stopped for %s: %v", permanentBackoff, err)
		return nil
	}
	return err
}

func (s *Syncer) sync(ctx context.Context) error {
	var raw json.RawMessage
	err := s.retry(ctx, func() error {
		return s.client().RPC(ctx, RPCName, struct{}{}, &raw)
	})
	if err != nil {
		return fmt.Errorf("%s: %w", RPCName, err)
	}
	next, err := decode(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", RPCName, err)
	}
	old, err := Load(s.path)
	if err != nil {
		log.Printf("Uninstall protection: replacing unreadable state: %v", err)
	}
	if old != nil && *old == next {
		return nil
	}
	if err := Save(s.path, next); err != nil {
		return err
	}
	if old == nil || old.Version != next.Version || old.Enabled != next.Enabled {
		log.Printf("Uninstall protection: synced version %d (enabled=%t, token hash present=%t)",
			next.Version, next.Enabled, next.TokenHash != "")
	}
	return nil
}

// decode parses the RPC's answer. salt and token_hash are null with
// protection off; they are dropped then, so a stale hash never lingers.
func decode(raw []byte) (State, error) {
	var r struct {
		Enabled   bool    `json:"enabled"`
		Version   int64   `json:"version"`
		Salt      *string `json:"salt"`
		TokenHash *string `json:"token_hash"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return State{}, fmt.Errorf("decode: %w", err)
	}
	s := State{Enabled: r.Enabled, Version: r.Version}
	if r.Enabled && r.Salt != nil && r.TokenHash != nil {
		s.Salt, s.TokenHash = *r.Salt, *r.TokenHash
	}
	if err := s.validate(); err != nil {
		return State{}, err
	}
	return s, nil
}

// permanent reports errors a retry on the next tick won't fix.
func permanent(err error) bool {
	if supabase.IsForbidden(err) || supabase.IsNotFound(err) {
		return true
	}
	e, ok := supabase.AsAPIError(err)
	return ok && e.Code == "P0002"
}
