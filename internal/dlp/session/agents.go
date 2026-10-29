package session

import (
	"context"
	"log"
	"sort"
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

	// label names a user for the status: its account name and session id
	// (the uid on macOS, where Users returns uids).
	label func(user string) (name, sessionID string)

	mu        sync.Mutex
	running   bool
	stopCh    chan struct{}
	loopWG    sync.WaitGroup
	installed bool
	firstPass bool                  // the first pass of this service run hasn't finished
	users     map[string]*agentUser // users with a graphical session, by Users() key
	setupErr  string                // why Install or Users last failed ("" when it didn't)
}

// agentUser is what the supervisor did for one user's helper.
type agentUser struct {
	state   string // stateStarting, stateRestarting or stateFailed
	lastErr string // the Start error while state is stateFailed
	// restart: the next Start must replace a running helper. Set for every
	// user on the first pass (the old one may run the binary from before a
	// self-update) and kept until a restart succeeds.
	restart bool
}

func newAgentSupervisor(hub *Hub, a userAgents) *agentSupervisor {
	return &agentSupervisor{
		Hub: hub, agents: a, poll: 30 * time.Second,
		label:     func(u string) (string, string) { return u, "" },
		firstPass: true,
		users:     map[string]*agentUser{},
	}
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
// existed, and retries a start that failed.
func (s *agentSupervisor) reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.installed {
		if err := s.agents.Install(); err != nil {
			log.Printf("DLP: install session helper definition: %v", err)
			s.setupErr = "install session helper definition: " + err.Error()
			return
		}
		s.installed = true
	}
	users, err := s.agents.Users()
	if err != nil {
		log.Printf("DLP: list graphical sessions: %v", err)
		s.setupErr = "list graphical sessions: " + err.Error()
		return
	}
	s.setupErr = ""
	connected := s.connected()
	present := map[string]bool{}
	for _, u := range users {
		present[u] = true
		au := s.users[u]
		if au == nil {
			au = &agentUser{restart: s.firstPass}
			s.users[u] = au
		} else if au.state != stateFailed && s.isConnected(connected, u) {
			continue
		}
		// Not connected (yet): Start again. It does nothing to a helper
		// that is running, and starts one that launchd/systemd loaded but
		// doesn't run (e.g. it exited cleanly when the old service stopped).
		if err := s.agents.Start(u, au.restart); err != nil {
			log.Printf("DLP: start session helper for %s: %v", u, err)
			au.state, au.lastErr = stateFailed, err.Error()
			continue // au.restart stays: the next pass tries the same again
		}
		au.state, au.lastErr = stateStarting, ""
		if au.restart {
			au.state = stateRestarting
		}
		au.restart = false
	}
	s.firstPass = false
	for u := range s.users {
		if !present[u] {
			delete(s.users, u) // logged out; a new login starts it again
		}
	}
}

// Sessions reports the connected helpers, plus each graphical session whose
// helper hasn't connected: "starting" / "restarting" after a successful
// Start, "start_failed" with the error after a failed one. When the
// definition can't be installed or the sessions can't be listed, one entry
// carries that error.
func (s *agentSupervisor) Sessions() []Info {
	out := s.Hub.Sessions()
	connected := connectedSet(out)
	s.mu.Lock()
	if s.setupErr != "" {
		out = append(out, Info{User: "all sessions", State: stateFailed, LastError: s.setupErr})
	}
	for u, au := range s.users {
		if s.isConnected(connected, u) {
			continue
		}
		name, sid := s.label(u)
		in := Info{User: name, State: au.state, SessionID: sid, LastError: au.lastErr}
		if in.LastError == "" {
			// Started, but the hub refused it or it left before hello.
			in.LastError = s.Hub.lastError(sid)
		}
		out = append(out, in)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// connected returns the users and session ids with a connected helper.
func (s *agentSupervisor) connected() map[string]bool { return connectedSet(s.Hub.Sessions()) }

func connectedSet(sessions []Info) map[string]bool {
	set := map[string]bool{}
	for _, in := range sessions {
		set[in.User] = true
		if in.SessionID != "" {
			set[in.SessionID] = true
		}
	}
	return set
}

// isConnected reports whether user (a Users() key) has a connected helper.
func (s *agentSupervisor) isConnected(connected map[string]bool, user string) bool {
	name, sid := s.label(user)
	return connected[user] || connected[name] || (sid != "" && connected[sid])
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
	// Unconditionally: a definition installed before an unclean restart, or
	// while DLP was on during a previous run, must not survive DLP being off.
	if users, err := s.agents.Users(); err == nil {
		for _, u := range users {
			if err := s.agents.Stop(u); err != nil {
				log.Printf("DLP: stop session helper for %s: %v", u, err)
			}
		}
	}
	if err := s.agents.Uninstall(); err != nil {
		log.Printf("DLP: remove session helper definition: %v", err)
	}
	s.installed = false
	s.users = map[string]*agentUser{}
	s.setupErr = ""
	s.firstPass = true
}
