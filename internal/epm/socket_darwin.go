//go:build darwin

package epm

import "context"

// SocketServer is the macOS enforcement transport. As of Phase 2 it is a
// thin wrapper around the shared Server core (server.go) plus a
// darwinTransport (transport_darwin.go, framing + peer identity) and a
// darwinLauncher (transport_darwin.go, launch) — evaluateAndLaunch and audit,
// previously implemented here directly, are now the one copy in
// Server.elevate/Server.audit that every platform shares.
type SocketServer struct {
	inner *Server
}

// NewSocketServer builds a SocketServer. rules supplies the live policy rule
// set (queried fresh per request) and auditor records every elevation
// decision.
func NewSocketServer(rules RuleProvider, auditor *Auditor) *SocketServer {
	srv := NewServer(newDarwinTransport(), darwinLauncher{}, darwinIdentifier{}, rules, auditor,
		WithRequestTimeout(unixSocketRequestTimeout),
		WithHashFile(func(path string) (string, error) { return computeFileHashFn(path) }),
	)
	return &SocketServer{inner: srv}
}

// Serve runs the accept loop until ctx is cancelled or Stop is called.
func (s *SocketServer) Serve(ctx context.Context) error {
	return s.inner.Serve(ctx)
}

// Stop closes the listener, unblocking any pending Accept.
func (s *SocketServer) Stop() {
	_ = s.inner.Stop()
}
