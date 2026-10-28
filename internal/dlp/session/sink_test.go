package session

import (
	"sync"

	"sentinelgo/internal/dlp/events"
)

// recordingSink collects events the hub passes on.
type recordingSink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (s *recordingSink) Emit(ev events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
}

func (s *recordingSink) events() []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.Event(nil), s.evs...)
}
