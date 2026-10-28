package session

import (
	"context"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/dlp/policy"
)

// userAgents is how macOS (launchd LaunchAgent) and Linux (systemd user
// unit + XDG autostart) run a helper in each graphical session: the OS's
// per-user service manager launches and restarts it, the service only
// installs the definition and nudges sessions that already exist.
type userAgents interface {
	// Install writes the agent definition (idempotent).
	Install() error
	// Uninstall removes it, so new logins don't start helpers.
	Uninstall() error
	// Users lists users with a graphical session.
	Users() ([]string, error)
	// Start starts the helper for user; restart replaces a running one
	// (after a self-update the old helper still runs the old binary).
	Start(user string, restart bool) error
	// Stop stops the helper for user.
	Stop(user string) error
}

// agentSupervisor runs helpers through userAgents while DLP enforces, and
// removes them when it stops.
type agentSupervisor struct {
	*Hub
	agents userAgents
	poll   time.Duration

	mu        sync.Mutex
	running   bool
	stopCh    chan struct{}
	loopWG    sync.WaitGroup
	installed bool
	restarted bool            // first start this service run replaces old helpers
	started   map[string]bool // users whose helper we started
}

func newAgentSupervisor(hub *Hub, a userAgents) *agentSupervisor {
	return &agentSupervisor{Hub: hub, agents: a, poll: 30 * time.Second, started: map[string]bool{}}
}

// Apply pushes p to the helpers and makes sure every graphical session has
// one.
func (s *agentSupervisor) Apply(ctx context.Context, p *policy.Compiled) {
	s.Hub.Apply(ctx, p)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.loopWG.Add(1)
	go s.loop(s.stopCh)
}

func (s *agentSupervisor) loop(stop chan struct{}) {
	defer s.loopWG.Done()
	t := time.NewTicker(s.poll)
	defer t.Stop()
	for {
		s.reconcile()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// reconcile installs the definition and starts helpers for sessions that
// don't have one yet. New logins also start it by themselves (the
// definition is installed globally); this covers sessions that already
// existed.
func (s *agentSupervisor) reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.installed {
		if err := s.agents.Install(); err != nil {
			log.Printf("DLP: install session helper definition: %v", err)
			return
		}
		s.installed = true
	}
	users, err := s.agents.Users()
	if err != nil {
		log.Printf("DLP: list graphical sessions: %v", err)
		return
	}
	present := map[string]bool{}
	for _, u := range users {
		present[u] = true
		if s.started[u] {
			continue
		}
		if err := s.agents.Start(u, !s.restarted); err != nil {
			log.Printf("DLP: start session helper for %s: %v", u, err)
			continue
		}
		s.started[u] = true
	}
	s.restarted = true
	for u := range s.started {
		if !present[u] {
			delete(s.started, u) // logged out; a new login starts it again
		}
	}
}

// Stop tells helpers to exit, stops their agents and uninstalls the
// definition so DLP stays off at the next login.
func (s *agentSupervisor) Stop() {
	s.mu.Lock()
	if s.running {
		s.running = false
		close(s.stopCh)
	}
	s.mu.Unlock()
	s.loopWG.Wait()

	s.Hub.Stop()

	s.mu.Lock()
	defer s.mu.Unlock()
	if users, err := s.agents.Users(); err == nil {
		for _, u := range users {
			if err := s.agents.Stop(u); err != nil {
				log.Printf("DLP: stop session helper for %s: %v", u, err)
			}
		}
	}
	if s.installed {
		if err := s.agents.Uninstall(); err != nil {
			log.Printf("DLP: remove session helper definition: %v", err)
		}
		s.installed = false
	}
	s.started = map[string]bool{}
	s.restarted = false
}
