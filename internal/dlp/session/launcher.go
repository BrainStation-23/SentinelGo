package session

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"sentinelgo/internal/dlp/policy"
)

// Process is a launched helper process.
type Process interface {
	Wait() error // returns when the process exits
	Kill() error
}

// Launcher starts helpers in interactive sessions (per OS).
type Launcher interface {
	// Sessions lists the interactive sessions that should have a helper.
	Sessions() ([]string, error)
	// Start launches a helper in session.
	Start(session string) (Process, error)
}

// Helper states reported in the status.
const (
	stateStarting   = "starting"
	stateRestarting = "restarting"
	stateFailed     = "start_failed"
)

// launchSupervisor keeps exactly one helper per interactive session: it
// starts missing ones, restarts exited ones with backoff, stops those whose
// session ended, and serves them through the Hub.
type launchSupervisor struct {
	*Hub
	launcher Launcher
	poll     time.Duration
	backoff  func(restarts int) time.Duration
	stopWait time.Duration // how long Stop waits for helpers before killing

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	loopWG  sync.WaitGroup
	helpers map[string]*managedHelper
}

type managedHelper struct {
	proc     Process
	exited   chan struct{} // closed when proc exits; nil if not running
	restarts int
	next     time.Time // earliest (re)start
	state    string
}

func newLaunchSupervisor(hub *Hub, l Launcher) *launchSupervisor {
	return &launchSupervisor{
		Hub:      hub,
		launcher: l,
		poll:     5 * time.Second,
		backoff:  func(n int) time.Duration { return min(time.Second<<min(n, 6), time.Minute) },
		stopWait: 3 * time.Second,
		helpers:  map[string]*managedHelper{},
	}
}

// Apply pushes p to the helpers and makes sure they run.
func (s *launchSupervisor) Apply(ctx context.Context, p *policy.Compiled) {
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

func (s *launchSupervisor) loop(stop chan struct{}) {
	defer s.loopWG.Done()
	t := time.NewTicker(s.poll)
	defer t.Stop()
	for {
		s.reconcile(time.Now())
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// reconcile brings the helpers in line with the current sessions.
func (s *launchSupervisor) reconcile(now time.Time) {
	sessions, err := s.launcher.Sessions()
	if err != nil {
		log.Printf("DLP: list interactive sessions: %v", err)
		return
	}
	want := map[string]bool{}
	for _, id := range sessions {
		want[id] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, h := range s.helpers {
		if !want[id] {
			if h.exited != nil {
				_ = h.proc.Kill()
			}
			delete(s.helpers, id)
			s.setLastError(id, "")
			log.Printf("DLP: session %s ended; helper stopped", id)
		}
	}
	for id := range want {
		h := s.helpers[id]
		if h == nil {
			h = &managedHelper{}
			s.helpers[id] = h
		}
		s.tend(id, h, now)
	}
}

// tend starts h if it isn't running and its backoff has passed. s.mu is held.
func (s *launchSupervisor) tend(id string, h *managedHelper, now time.Time) {
	if h.exited != nil {
		select {
		case <-h.exited:
			h.exited = nil
			h.restarts++
			h.next = now.Add(s.backoff(h.restarts))
			h.state = stateRestarting
			log.Printf("DLP: helper in session %s exited (restart %d)", id, h.restarts)
		default:
			return // still running
		}
	}
	if now.Before(h.next) {
		return
	}
	p, err := s.launcher.Start(id)
	if err != nil {
		h.restarts++
		h.next = now.Add(s.backoff(h.restarts))
		if h.state != stateFailed {
			log.Printf("DLP: start helper in session %s: %v", id, err)
		}
		h.state = stateFailed
		return
	}
	h.proc = p
	h.exited = make(chan struct{})
	h.state = stateStarting // the Hub reports it as running once it connects
	go func(p Process, done chan struct{}) {
		_ = p.Wait()
		close(done)
	}(p, h.exited)
}

// Stop stops the launch loop, tells the helpers to exit and kills any that
// don't within stopWait.
func (s *launchSupervisor) Stop() {
	s.mu.Lock()
	if s.running {
		s.running = false
		close(s.stopCh)
	}
	s.mu.Unlock()
	s.loopWG.Wait()

	s.Hub.Stop() // sends stop to every connected helper

	s.mu.Lock()
	helpers := s.helpers
	s.helpers = map[string]*managedHelper{}
	s.mu.Unlock()
	deadline := time.After(s.stopWait)
	for _, h := range helpers {
		if h.exited == nil {
			continue
		}
		select {
		case <-h.exited:
		case <-deadline:
			_ = h.proc.Kill()
		}
	}
}

// Sessions reports the connected helpers, plus sessions whose helper is
// starting or restarting, with why its last connection failed.
func (s *launchSupervisor) Sessions() []Info {
	out := s.Hub.Sessions()
	connected := map[string]bool{}
	for _, in := range out {
		connected[in.SessionID] = true
	}
	s.mu.Lock()
	for id, h := range s.helpers {
		// A started helper shows as "starting" until it connects; then the
		// hub lists it.
		if !connected[id] {
			out = append(out, Info{User: "session " + id, State: h.state, SessionID: id, LastError: s.lastError(id)})
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}
