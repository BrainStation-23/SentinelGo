//go:build linux

package epm

import (
	"context"
	"log"
)

// Service ties the policy engine's data dependencies (RuleProvider, Auditor)
// to the platform enforcement transport — a Unix Domain Socket server on
// Linux — and manages its lifecycle. Callers (internal/main_integration.go)
// construct one Service per agent run when EPM is enabled; the same exported
// API exists on every platform (see service_windows.go, service_darwin.go,
// service_other.go) so the caller needs no build tags of its own.
type Service struct {
	socket *SocketServer
	cancel context.CancelFunc
	done   chan struct{}
}

// NewService builds a Service backed by a Unix Domain Socket IPC server.
// rules supplies the live policy rule set and auditor records every
// elevation decision; internal/store.EPMStore implements both.
func NewService(rules RuleProvider, auditor *Auditor) *Service {
	return NewServiceWithOptions(rules, auditor, ServiceOptions{})
}

// NewServiceWithOptions builds a Service honouring opts. No ServiceOptions
// field currently applies on Linux: the daemon already runs as root and
// LaunchAsUser retains that privilege, so there is no token selection to make.
func NewServiceWithOptions(rules RuleProvider, auditor *Auditor, _ ServiceOptions) *Service {
	return &Service{socket: NewSocketServer(rules, auditor)}
}

// Start begins accepting elevation requests in the background. It returns
// once the socket server goroutine has been launched; Serve failures after
// that point are logged, not returned, since Start's caller (agent startup)
// treats EPM as a best-effort optional component like every other scheduled
// service.
func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})

	go func() {
		defer close(s.done)
		if err := s.socket.Serve(runCtx); err != nil && runCtx.Err() == nil {
			log.Printf("epm: socket server stopped unexpectedly: %v", err)
		}
	}()

	log.Printf("epm: Unix Domain Socket IPC server listening on %s", SocketPath)
	return nil
}

// Stop cancels the accept loop and waits for the server goroutine to exit.
func (s *Service) Stop() error {
	if s.cancel == nil {
		return nil
	}
	s.cancel()
	s.socket.Stop()
	<-s.done
	return nil
}
