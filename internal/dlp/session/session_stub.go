package session

import (
	"context"
	"log"
	"runtime"
	"sync"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// manualSupervisor serves the helper endpoint but doesn't launch helpers: a
// helper started by hand (`sentinelgo dlp-session` in a user session)
// connects and enforces. Each OS replaces it with a launcher.
type manualSupervisor struct {
	*Hub
	warnOnce sync.Once
}

// New returns the session supervisor for this platform. Helper events go to
// sink.
func New(sink channel.EventSink) Supervisor {
	return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
}

func (s *manualSupervisor) Apply(ctx context.Context, p *policy.Compiled) {
	s.warnOnce.Do(func() {
		log.Printf("DLP: session helpers are not launched automatically on %s yet; "+
			"run `sentinelgo dlp-session` in a user session to enforce", runtime.GOOS)
	})
	s.Hub.Apply(ctx, p)
}
