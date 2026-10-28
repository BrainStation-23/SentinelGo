package session

import (
	"context"
	"log"
	"runtime"
	"sync"

	"sentinelgo/internal/dlp/policy"
)

// stubSupervisor is the supervisor on a platform without a helper launcher. It
// logs once that nothing is enforced, so "no DLP events" is never mistaken for
// "nothing matched".
type stubSupervisor struct {
	warnOnce sync.Once
}

// New returns the session supervisor for this platform.
func New() Supervisor { return &stubSupervisor{} }

func (s *stubSupervisor) Apply(context.Context, *policy.Compiled) {
	s.warnOnce.Do(func() {
		log.Printf("DLP: session helpers are not supported on %s yet; policy received but not enforced", runtime.GOOS)
	})
}

func (s *stubSupervisor) Stop() {}

func (s *stubSupervisor) Sessions() []Info { return nil }
