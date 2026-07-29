//go:build windows

package epm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsTransport implements Transport over a Windows Named Pipe. It is the
// Phase 2 home of what pipe_windows.go's PipeServer used to do directly:
// CreateNamedPipe/ConnectNamedPipe framing and per-connection peer identity
// resolution. See pipe_windows.go for the thin PipeServer wrapper that keeps
// the pre-Phase-2 public API (NewPipeServer, .Serve, .Stop) working
// unmodified for pipe_integration_windows_test.go.
//
// closed makes Close idempotent AND persistent, unlike a bare CancelIoEx on
// the single currently-blocked instance: Server.Serve's accept loop retries
// on any Accept error whose ctx is not yet Done (see server.go), and a
// caller's Stop()/Close() is not guaranteed to run after ctx has already been
// cancelled — the existing pipe_integration_windows_test.go cleanup order is
// Stop() then cancel(), for instance. Without this flag, a retry raced
// against a Close() can create and start blocking on a BRAND NEW pipe
// instance that Close() never gets another chance to cancel, deadlocking
// Serve forever (observed: TestPipeServer_EndToEnd_AllowedRequestLaunches
// hanging under `go test ./...`, though never under an isolated run — a
// timing-dependent race, not a deterministic one, which is exactly why it
// only surfaced under different goroutine scheduling in the full suite).
// Checking closed at the top of Accept, before ever calling
// CreateNamedPipe/ConnectNamedPipe again, closes that window: once Close has
// run, no further instance is ever created to block on.
type windowsTransport struct {
	sa *windows.SecurityAttributes // built once in Listen

	mu      sync.Mutex
	current windows.Handle // the instance currently blocked in ConnectNamedPipe, if any
	closed  bool
}

func newWindowsTransport() *windowsTransport { return &windowsTransport{} }

// Identity-resolution seams: the OS-privileged calls needed to turn a raw
// pipe connection into a PeerIdentity. Kept as package-level function vars —
// exactly the pattern pipe_windows.go established before Phase 2 — so
// pipe_integration_windows_test.go's existing stubs keep controlling this
// code even though it now lives in Accept rather than evaluateAndLaunch.
var (
	sessionIDForProcessFn = sessionIDForProcess
	queryUserTokenFn      = QueryUserToken
	userIDForTokenFn      = userIDForToken
)

// Listen builds the pipe's security descriptor once, for every instance
// Accept creates. GENERIC_ALL to Authenticated Users (D:(A;;GA;;;AU)) is
// unchanged from before Phase 2; the SACL (S:(ML;;NW;;;ME)) is new — a
// mandatory-integrity label denying write-up, so a low-integrity process
// cannot write to the pipe. This has no effect on the wire format itself,
// only on which processes may open a handle at all.
func (t *windowsTransport) Listen(ctx context.Context) error {
	sd, err := windows.SecurityDescriptorFromString(`D:(A;;GA;;;AU)S:(ML;;NW;;;ME)`)
	if err != nil {
		return fmt.Errorf("build pipe security descriptor: %w", err)
	}
	t.sa = &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	return nil
}

// Accept blocks until a client connects, then resolves that client's real
// identity from the OS — never from anything the client will later send —
// and returns a Conn carrying it. A failure during identity resolution is
// reported to the client as a proper error Response (matching pre-Phase-2
// behavior, where the same failure was surfaced from inside
// evaluateAndLaunch) rather than silently dropping the connection; Accept
// still returns an error so Server.Serve's loop logs and moves on to the
// next client.
func (t *windowsTransport) Accept(ctx context.Context) (Conn, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("transport closed")
	}

	handle, err := t.createInstance()
	if err != nil {
		return nil, fmt.Errorf("CreateNamedPipe: %w", err)
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("transport closed")
	}
	t.current = handle
	t.mu.Unlock()

	// ERROR_PIPE_CONNECTED means a client raced in between create and
	// connect and is already attached — not a failure.
	if err := windows.ConnectNamedPipe(handle, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		_ = windows.CloseHandle(handle)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ConnectNamedPipe: %w", err)
	}

	var clientPID uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &clientPID); err != nil {
		failConnection(handle, fmt.Sprintf("resolve client process: %v", err))
		return nil, fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}

	sessionID, err := sessionIDForProcessFn(clientPID)
	if err != nil {
		failConnection(handle, fmt.Sprintf("resolve session: %v", err))
		return nil, fmt.Errorf("resolve session: %w", err)
	}

	userToken, err := queryUserTokenFn(sessionID)
	if err != nil {
		failConnection(handle, fmt.Sprintf("resolve user token: %v", err))
		return nil, fmt.Errorf("resolve user token: %w", err)
	}

	userID, err := userIDForTokenFn(userToken)
	if err != nil {
		_ = userToken.Close()
		failConnection(handle, fmt.Sprintf("resolve user identity: %v", err))
		return nil, fmt.Errorf("resolve user identity: %w", err)
	}

	return &windowsConn{
		handle: handle,
		peer: PeerIdentity{
			PID: clientPID, SessionID: sessionID, UserID: userID,
			Cred: userToken, // consumed by windowsLauncher.Launch, closed by windowsConn.Close
		},
	}, nil
}

// failConnection writes a Response carrying message to handle before closing
// it — used when identity resolution fails partway through Accept, so the
// client gets an actionable error instead of an abrupt disconnect. Best
// effort: if the write itself fails there is nothing more to do.
func failConnection(handle windows.Handle, message string) {
	defer func() {
		_ = windows.DisconnectNamedPipe(handle)
		_ = windows.CloseHandle(handle)
	}()
	data, err := encodeResponse(Response{Error: message})
	if err != nil {
		return
	}
	var written uint32
	_ = windows.WriteFile(handle, data, &written, nil)
}

// Addr identifies this transport for logging.
func (t *windowsTransport) Addr() string { return PipeName }

// Close marks the transport closed (see the closed field's doc comment for
// why this must be permanent, not just a one-shot cancel) and unblocks a
// pending ConnectNamedPipe call so Serve can observe it promptly instead of
// waiting indefinitely for the next client. Idempotent.
func (t *windowsTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	handle := t.current
	t.mu.Unlock()
	if handle != 0 {
		_ = windows.CancelIoEx(handle, nil)
	}
	return nil
}

func (t *windowsTransport) createInstance() (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		pipeBufferSize,
		pipeBufferSize,
		0, // default timeout
		t.sa,
	)
}

// windowsConn wraps one connected pipe instance. ReadMessage/WriteMessage are
// byte-identical to pre-Phase-2 pipe_windows.go: one ReadFile == one
// WriteFile, no length prefix, because PIPE_TYPE_MESSAGE framing already
// delivers exactly one message per call.
type windowsConn struct {
	handle windows.Handle
	peer   PeerIdentity

	mu    sync.Mutex
	timer *time.Timer // armed by SetDeadline; nil until first call
}

func (c *windowsConn) Peer() PeerIdentity { return c.peer }

func (c *windowsConn) ReadMessage() ([]byte, error) {
	buf := make([]byte, pipeBufferSize)
	var n uint32
	if err := windows.ReadFile(c.handle, buf, &n, nil); err != nil {
		return nil, fmt.Errorf("ReadFile: %w", err)
	}
	return buf[:n], nil
}

func (c *windowsConn) WriteMessage(msg []byte) error {
	var written uint32
	if err := windows.WriteFile(c.handle, msg, &written, nil); err != nil {
		return fmt.Errorf("WriteFile: %w", err)
	}
	return nil
}

// SetDeadline is a new capability with zero wire impact: pre-Phase-2 Windows
// had no per-request timeout at all (only the Unix transports did, via
// net.Conn.SetDeadline). A background timer cancels the pending I/O if the
// deadline passes before Close stops it.
func (c *windowsConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	d := time.Until(t)
	if d <= 0 {
		_ = windows.CancelIoEx(c.handle, nil)
		return nil
	}
	handle := c.handle
	c.timer = time.AfterFunc(d, func() {
		_ = windows.CancelIoEx(handle, nil)
	})
	return nil
}

func (c *windowsConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()

	_ = windows.DisconnectNamedPipe(c.handle)
	err := windows.CloseHandle(c.handle)
	if tok, ok := c.peer.Cred.(windows.Token); ok {
		_ = tok.Close()
	}
	return err
}
