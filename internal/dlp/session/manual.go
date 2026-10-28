package session

import (
	"context"
	"log"
	"runtime"
	"sync"

	"sentinelgo/internal/dlp/policy"
)

// manualSupervisor serves the helper endpoint but doesn't launch helpers: a
// helper started by hand (`sentinelgo dlp-session` in a user session)
// connects and enforces. Used where no launcher exists (yet).
type manualSupervisor struct {
	*Hub
	warnOnce sync.Once
}

func (s *manualSupervisor) Apply(ctx context.Context, p *policy.Compiled) {
	s.warnOnce.Do(func() {
		log.Printf("DLP: session helpers are not launched automatically on %s; "+
			"run `sentinelgo dlp-session` in a user session to enforce", runtime.GOOS)
	})
	s.Hub.Apply(ctx, p)
}
