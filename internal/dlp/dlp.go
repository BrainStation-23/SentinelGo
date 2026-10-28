// Package dlp is the agent's Data Loss Prevention subsystem (epic #257). The
// Manager runs in the service: it decides from the kill switches whether DLP
// is enforced, and hands the compiled policy to the session supervisor, which
// runs one helper per interactive session. The helpers do the watching and
// matching; content never leaves the user's process unless it is flagged, and
// then only masked.
//
// Subpackages: policy (bundle model and compile), detect (detection engine),
// events (evidence model), channel (Channel interface and the clipboard
// channel), session (helper supervisor), ipc (service↔helper protocol) and
// notify (desktop notifications).
package dlp

import (
	"context"
	"log"
	"sync"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/session"
)

// State is what the Manager decided from the kill switches.
type State string

const (
	// StateStopped: Start hasn't run yet, or Stop has.
	StateStopped State = "stopped"
	// StateDisabledLocal: dlp_enabled is false in config.json. Wins over the
	// server.
	StateDisabledLocal State = "disabled_local"
	// StateNoPolicy: no bundle has ever been fetched (fail-open).
	StateNoPolicy State = "no_policy"
	// StateDisabledServer: the bundle says enabled:false (org kill switch).
	StateDisabledServer State = "disabled_server"
	// StateIdle: DLP is on but every channel module is switched off.
	StateIdle State = "idle"
	// StateEnforcing: helpers run and enforce the bundle.
	StateEnforcing State = "enforcing"
)

// Decide applies the kill-switch truth table (epic #257) to the local switch
// and the last-known bundle (nil when none was ever fetched).
func Decide(localEnabled bool, b *policy.Bundle) State {
	switch {
	case !localEnabled:
		return StateDisabledLocal
	case b == nil:
		return StateNoPolicy
	case !b.Enabled:
		return StateDisabledServer
	case !b.AnyChannelEnabled():
		return StateIdle
	default:
		return StateEnforcing
	}
}

// BundleSource supplies the last-known bundle at startup, before any network
// call, so enforcement resumes instantly after a reboot.
type BundleSource interface {
	// Load returns the last-known bundle, or nil when there is none.
	Load() (*policy.Bundle, error)
}

// Manager owns the DLP lifecycle on the service side.
type Manager struct {
	localEnabled bool
	source       BundleSource
	sup          session.Supervisor

	mu       sync.Mutex
	ctx      context.Context
	started  bool
	state    State
	bundle   *policy.Bundle
	compiled *policy.Compiled // of bundle, while enforcing
}

// NewManager returns a Manager. localEnabled is the config's dlp_enabled.
// source may be nil (no cached bundle).
func NewManager(localEnabled bool, source BundleSource, sup session.Supervisor) *Manager {
	return &Manager{
		localEnabled: localEnabled,
		source:       source,
		sup:          sup,
		state:        StateStopped,
	}
}

// Start loads the last-known bundle and starts enforcing it if the kill
// switches allow. With dlp_enabled false it starts nothing.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.localEnabled {
		m.state = StateDisabledLocal
		log.Printf("DLP: disabled on this device (dlp_enabled=false); not starting")
		return nil
	}

	m.ctx = ctx
	m.started = true
	if m.bundle == nil && m.source != nil {
		b, err := m.source.Load()
		if err != nil {
			log.Printf("DLP: could not load the cached policy, waiting for the server: %v", err)
		}
		m.bundle = b
	}
	m.applyLocked()
	return nil
}

// Apply switches to bundle b. A nil b is ignored, so a failed fetch keeps the
// last-known bundle in force. Before Start, b is kept for Start to apply.
func (m *Manager) Apply(b *policy.Bundle) {
	if b == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bundle = b
	if m.started {
		m.applyLocked()
	}
}

// applyLocked drives the supervisor to match the current state. m.mu is held.
func (m *Manager) applyLocked() {
	next := Decide(m.localEnabled, m.bundle)
	if next != m.state {
		log.Printf("DLP: state %s -> %s", m.state, next)
	}
	m.state = next

	if next == StateEnforcing {
		if m.compiled == nil || m.compiled.Version != m.bundle.Version {
			m.compiled = policy.Compile(m.bundle)
			for _, ce := range m.compiled.CompileErrors {
				log.Printf("DLP: rule %s skipped: %s", ce.RuleID, ce.Error)
			}
		}
		m.sup.Apply(m.ctx, m.compiled)
		return
	}
	m.compiled = nil
	m.sup.Stop()
}

// Stop stops every helper. Later Apply calls only record the bundle.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return
	}
	m.started = false
	m.state = StateStopped
	m.compiled = nil
	m.sup.Stop()
}

// Snapshot is what the Manager has applied, for status reports.
type Snapshot struct {
	State         State
	Version       string // of the last-known bundle; "" when none
	CompileErrors []detect.CompileError
	Sessions      []session.Info
}

// Snapshot returns the current state. Safe for concurrent use.
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{State: m.state}
	if m.bundle != nil {
		s.Version = m.bundle.Version
	}
	if m.compiled != nil {
		s.CompileErrors = m.compiled.CompileErrors
	}
	if m.started {
		s.Sessions = m.sup.Sessions()
	}
	return s
}

// currentBundle returns the last-known bundle (nil when none). A bundle is
// never mutated after Apply, so sharing the pointer is safe.
func (m *Manager) currentBundle() *policy.Bundle {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bundle
}

// State returns the current decision.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}
