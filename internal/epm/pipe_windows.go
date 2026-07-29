//go:build windows

package epm

import "context"

// PipeName is the Named Pipe path the user-space EPM client
// (cmd/sentinelgo-epm) connects to. Only one instance of the pipe is ever
// listening at a time; each connection is handled and closed before the next
// instance is created.
const PipeName = `\\.\pipe\sentinelgo-epm`

// pipeBufferSize is generous enough for the small JSON request/response
// messages this protocol exchanges; PIPE_TYPE_MESSAGE framing means each
// WriteFile call arrives as one discrete ReadFile on the other end, so there
// is no need for length-prefixing on top of it.
const pipeBufferSize = 64 * 1024

// PipeServer is the Windows enforcement transport. As of Phase 2 it is a
// thin wrapper around the shared Server core (server.go) plus a
// windowsTransport (transport_windows.go, framing + peer identity) and a
// windowsLauncher (launcher_iface_windows.go, elevation token + launch) —
// evaluateAndLaunch and audit, previously implemented here directly, are now
// the one copy in Server.elevate/Server.audit that every platform shares.
//
// Kept as a named type — rather than callers constructing a bare *Server
// directly — specifically so NewPipeServer/NewPipeServerWithTokenType's
// existing signatures keep working unmodified: pipe_integration_windows_test.go
// depends on both, and preserving them exactly (not just their effect) is
// what makes that test a meaningful, unmodified merge gate rather than one
// quietly rewritten to fit a new API.
type PipeServer struct {
	inner *Server
}

// NewPipeServer builds a PipeServer. rules supplies the live policy rule set
// (queried fresh per request) and auditor records every elevation decision.
// Uses the default elevation token type; see NewPipeServerWithTokenType.
func NewPipeServer(rules RuleProvider, auditor *Auditor) *PipeServer {
	return NewPipeServerWithTokenType(rules, auditor, TokenElevated)
}

// NewPipeServerWithTokenType builds a PipeServer that derives elevation
// tokens as tokenType prescribes. An empty or unrecognised tokenType falls
// back to TokenElevated.
func NewPipeServerWithTokenType(rules RuleProvider, auditor *Auditor, tokenType TokenType) *PipeServer {
	if !tokenType.Valid() {
		tokenType = TokenElevated
	}
	transport := newWindowsTransport()
	launcher := &windowsLauncher{tokenType: tokenType}
	srv := NewServer(transport, launcher, windowsIdentifier{}, rules, auditor,
		WithHashFile(func(path string) (string, error) { return computeFileHashFn(path) }),
	)
	return &PipeServer{inner: srv}
}

// Serve runs the accept loop until ctx is cancelled or Stop is called.
func (p *PipeServer) Serve(ctx context.Context) error {
	return p.inner.Serve(ctx)
}

// Stop unblocks a pending ConnectNamedPipe call so Serve can observe context
// cancellation promptly instead of waiting indefinitely for the next client.
func (p *PipeServer) Stop() {
	_ = p.inner.Stop()
}
