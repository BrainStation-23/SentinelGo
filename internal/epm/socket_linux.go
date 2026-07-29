//go:build linux

package epm

import "context"

// SocketServer is the Linux enforcement transport. As of Phase 2 it is a
// thin wrapper around the shared Server core (server.go) plus a
// linuxTransport (transport_linux.go, framing + peer identity) and a
// linuxLauncher (transport_linux.go, launch) — evaluateAndLaunch and audit,
// previously implemented here directly, are now the one copy in
// Server.elevate/Server.audit that every platform shares.
//
// Kept as a named type — rather than callers constructing a bare *Server
// directly — for symmetry with PipeServer (pipe_windows.go) and so a future
// Linux-specific option (mirroring NewPipeServerWithTokenType) has an
// obvious home.
type SocketServer struct {
	inner *Server
}

// NewSocketServer builds a SocketServer. rules supplies the live policy rule
// set (queried fresh per request) and auditor records every elevation
// decision.
func NewSocketServer(rules RuleProvider, auditor *Auditor) *SocketServer {
	srv := NewServer(newLinuxTransport(), linuxLauncher{}, linuxIdentifier{}, rules, auditor,
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
