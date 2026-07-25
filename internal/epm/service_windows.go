//go:build windows

package epm

import (
	"context"
	"log"
)

// Service ties the policy engine's data dependencies (RuleProvider, Auditor)
// to the platform enforcement transport — a Named Pipe server on Windows —
// and manages its lifecycle. Callers (internal/main_integration.go) construct
// one Service per agent run when EPM is enabled; the same exported API exists
// on every platform (see service_other.go for the non-Windows stub) so the
// caller needs no build tags of its own.
type Service struct {
	pipe   *PipeServer
	cancel context.CancelFunc
	done   chan struct{}
}

// NewService builds a Service backed by a Named Pipe IPC server. rules
// supplies the live policy rule set and auditor records every elevation
// decision; internal/store.EPMStore implements both.
func NewService(rules RuleProvider, auditor *Auditor) *Service {
	return &Service{pipe: NewPipeServer(rules, auditor)}
}

// Start begins accepting elevation requests in the background. It returns
// once the pipe server goroutine has been launched; Serve failures after that
// point are logged, not returned, since Start's caller (agent startup) treats
// EPM as a best-effort optional component like every other scheduled service.
func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})

	go func() {
		defer close(s.done)
		if err := s.pipe.Serve(runCtx); err != nil && runCtx.Err() == nil {
			log.Printf("epm: pipe server stopped unexpectedly: %v", err)
		}
	}()

	log.Printf("epm: Named Pipe IPC server listening on %s", PipeName)
	return nil
}

// Stop cancels the accept loop, unblocks any pending connect, and waits for
// the server goroutine to exit.
func (s *Service) Stop() error {
	if s.cancel == nil {
		return nil
	}
	s.cancel()
	s.pipe.Stop()
	<-s.done
	return nil
}
