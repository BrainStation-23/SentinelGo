package dlp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/session"
)

// ErrStatusRejected is returned by a Fetcher when the server refused the
// status report as malformed or too large (PostgREST 22023). The poll is
// retried once without the status, so the policy still arrives.
var ErrStatusRejected = errors.New("DLP status rejected by the server")

// Status is what this device actually applied, piggy-backed on the policy
// poll (agent_get_dlp_policy p_status). The server rejects it over 64 KB.
type Status struct {
	AppliedVersion     string                `json:"applied_version"`
	AgentVersion       string                `json:"agent_version"`
	Capabilities       map[string]string     `json:"capabilities"`
	DetectorsSupported []string              `json:"detectors_supported"`
	CompileErrors      []detect.CompileError `json:"compile_errors"`
	Sessions           []session.Info        `json:"sessions"`
}

// Status size caps, keeping the report well under the server's 64 KB limit.
const (
	maxStatusCompileErrors = 100
	maxStatusErrorLen      = 200
	maxStatusSessions      = 100
)

// FetchResult is the server's answer to a poll: unchanged, or a new bundle
// (Raw, decoded by the Syncer).
type FetchResult struct {
	Unchanged bool
	Raw       []byte
}

// Fetcher calls agent_get_dlp_policy. knownVersion is "" when the device has
// no bundle; status is nil to leave the last report in place.
type Fetcher interface {
	FetchPolicy(ctx context.Context, knownVersion string, status *Status) (FetchResult, error)
}

// BundleStore persists the last-known bundle (policy.Cache in production).
type BundleStore interface {
	BundleSource
	Save(b *policy.Bundle) error
}

// Syncer polls for the device's bundle, caches it and applies it. It runs
// from the dlp-policy-sync scheduler task, which ticks every minute; Due says
// whether this tick should poll.
type Syncer struct {
	fetcher      Fetcher
	store        BundleStore
	mgr          *Manager
	agentVersion string
	capabilities func() map[string]string
	now          func() time.Time

	mu         sync.Mutex
	next       time.Time // zero: poll on the next tick
	sentStatus [32]byte  // hash of the last status the server accepted
	statusSent bool
	syncErrors []detect.CompileError // bundle-level problems to report
}

// NewSyncer returns a Syncer. capabilities reports each channel's capability
// ("supported" / "unsupported:<reason>").
func NewSyncer(f Fetcher, store BundleStore, mgr *Manager, agentVersion string, capabilities func() map[string]string) *Syncer {
	return &Syncer{
		fetcher:      f,
		store:        store,
		mgr:          mgr,
		agentVersion: agentVersion,
		capabilities: capabilities,
		now:          time.Now,
	}
}

// Due reports whether a poll is due.
func (s *Syncer) Due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.now().Before(s.next)
}

// PollNow makes the next Due return true (e.g. for a "push policy now" task).
func (s *Syncer) PollNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = time.Time{}
}

// Sync polls once. On a new bundle it caches it and applies it; when the
// bundle is unchanged nothing is rewritten. On error the last-known bundle
// stays in force and the next poll is a full interval later.
func (s *Syncer) Sync(ctx context.Context) error {
	snap := s.mgr.Snapshot()
	defer s.schedule()

	status, hash := s.status(snap)
	send := status
	if s.alreadySent(hash) {
		send = nil
	}
	res, err := s.fetcher.FetchPolicy(ctx, snap.Version, send)
	if errors.Is(err, ErrStatusRejected) {
		log.Printf("DLP: server rejected the status report; polling without it: %v", err)
		res, err = s.fetcher.FetchPolicy(ctx, snap.Version, nil)
		send = nil
	}
	if err != nil {
		return fmt.Errorf("DLP policy poll: %w", err)
	}
	if send != nil {
		s.markSent(hash)
	}
	if res.Unchanged {
		return nil
	}
	return s.apply(res.Raw)
}

// apply decodes, caches and applies a new bundle.
func (s *Syncer) apply(raw []byte) error {
	b, err := policy.Decode(raw)
	if err != nil {
		// Keep enforcing the last-known bundle; report why the new one wasn't
		// applied with the next status.
		s.setSyncError(err)
		return fmt.Errorf("DLP: new policy not applied: %w", err)
	}
	s.setSyncError(nil)
	if err := s.store.Save(b); err != nil {
		log.Printf("DLP: could not cache the policy (applied anyway): %v", err)
	}
	log.Printf("DLP: applying policy %s (enabled=%v, %d policies)", b.Version, b.Enabled, len(b.Policies))
	s.mgr.Apply(b)
	return nil
}

// schedule sets the next poll to the current bundle's interval plus up to 10%
// jitter, so devices that booted together don't poll together.
func (s *Syncer) schedule() {
	interval := s.mgr.currentBundle().PollInterval()
	jitter := time.Duration(randInt63n(int64(interval / 10)))
	s.mu.Lock()
	s.next = s.now().Add(interval + jitter)
	s.mu.Unlock()
}

// status builds the current status report and its hash.
func (s *Syncer) status(snap Snapshot) (*Status, [32]byte) {
	st := &Status{
		AppliedVersion:     snap.Version,
		AgentVersion:       s.agentVersion,
		Capabilities:       map[string]string{},
		DetectorsSupported: detect.SupportedDetectors(),
		CompileErrors:      []detect.CompileError{},
		Sessions:           []session.Info{},
	}
	if s.capabilities != nil {
		st.Capabilities = s.capabilities()
	}
	s.mu.Lock()
	errs := append(append([]detect.CompileError{}, s.syncErrors...), snap.CompileErrors...)
	s.mu.Unlock()
	for _, ce := range errs {
		if len(st.CompileErrors) == maxStatusCompileErrors {
			break
		}
		if len(ce.Error) > maxStatusErrorLen {
			ce.Error = ce.Error[:maxStatusErrorLen]
		}
		st.CompileErrors = append(st.CompileErrors, ce)
	}
	if len(snap.Sessions) > 0 {
		st.Sessions = snap.Sessions[:min(len(snap.Sessions), maxStatusSessions)]
	}
	data, _ := json.Marshal(st)
	return st, sha256.Sum256(data)
}

func (s *Syncer) alreadySent(hash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusSent && s.sentStatus == hash
}

func (s *Syncer) markSent(hash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentStatus, s.statusSent = hash, true
}

// setSyncError records (or with nil clears) why the last bundle wasn't applied.
func (s *Syncer) setSyncError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncErrors = nil
	if err != nil {
		s.syncErrors = []detect.CompileError{{Error: err.Error()}}
	}
}

// randInt63n returns a random int64 in [0, n), or 0 when n <= 0.
func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return n / 2
	}
	return int64(binary.BigEndian.Uint64(buf[:])>>1) % n
}
