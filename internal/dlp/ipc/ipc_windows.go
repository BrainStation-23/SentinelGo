//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultAddress is the service's pipe.
const DefaultAddress = `\\.\pipe\sentinelgo-dlp`

// pipeDACL: SYSTEM and Administrators full access, interactive users
// read/write (connect). Remote clients are rejected by the pipe mode.
const pipeDACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// pipeSDDLs are tried in order. The service (LocalSystem) owns the pipe as
// SYSTEM, which is what helpers check (ServerIdentity); a non-SYSTEM caller
// (tests, a manual run) can't set that owner and falls back to its token's
// default owner.
var pipeSDDLs = []string{"O:SY" + pipeDACL, pipeDACL}

const pipeBufferSize = 64 << 10

// ErrClosed is returned by Accept after Close.
var ErrClosed = errors.New("ipc: listener closed")

type pipeListener struct {
	addr    string
	sa      *windows.SecurityAttributes
	closeEv windows.Handle

	mu        sync.Mutex
	next      windows.Handle // the instance the next Accept waits on
	closed    bool
	accepting sync.WaitGroup // Accepts that may still wait on closeEv
}

// Listen creates the pipe. The first instance uses FILE_FLAG_FIRST_PIPE_INSTANCE,
// so Listen fails if another process already owns the name (pipe squatting).
func Listen(addr string) (Listener, error) {
	return listen(addr, pipeSDDLs)
}

// listen creates the pipe with the first of sddls whose owner this process
// may set.
func listen(addr string, sddls []string) (Listener, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("ipc: create event: %w", err)
	}
	l := &pipeListener{addr: addr, closeEv: ev}
	err = errors.New("ipc: no pipe security descriptor")
	for _, sddl := range sddls {
		var sd *windows.SECURITY_DESCRIPTOR
		if sd, err = windows.SecurityDescriptorFromString(sddl); err != nil {
			err = fmt.Errorf("ipc: pipe security descriptor: %w", err)
			break
		}
		l.sa = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		var h windows.Handle
		if h, err = l.newInstance(true); err == nil {
			l.next = h
			return l, nil
		}
		if !errors.Is(err, windows.ERROR_INVALID_OWNER) {
			break
		}
	}
	_ = windows.CloseHandle(ev)
	return nil, err
}

func (l *pipeListener) newInstance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.addr)
	if err != nil {
		return windows.InvalidHandle, err
	}
	mode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	h, err := windows.CreateNamedPipe(name, mode,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, pipeBufferSize, pipeBufferSize, 0, l.sa)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("ipc: create pipe %s: %w", l.addr, err)
	}
	return h, nil
}

// Accept waits for a helper to connect and returns the connection.
func (l *pipeListener) Accept() (Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	h := l.next
	l.next = windows.InvalidHandle
	l.accepting.Add(1)
	l.mu.Unlock()
	defer l.accepting.Done()

	if h == windows.InvalidHandle {
		var err error
		if h, err = l.newInstance(false); err != nil {
			return nil, err
		}
	}
	if err := l.connect(h); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return newPipeConn(h)
}

// connect waits for a client on instance h, or for Close.
func (l *pipeListener) connect(h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return fmt.Errorf("ipc: connect pipe: %w", err)
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, l.closeEv}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if which != windows.WAIT_OBJECT_0 {
		_ = windows.CancelIoEx(h, &ov)
		var n uint32
		_ = windows.GetOverlappedResult(h, &ov, &n, true)
		return ErrClosed
	}
	var n uint32
	if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
		return fmt.Errorf("ipc: connect pipe: %w", err)
	}
	return nil
}

// Close stops Accept, waits for it to return and releases the listener's
// handles. Connections already accepted stay open.
func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	_ = windows.SetEvent(l.closeEv)
	if l.next != windows.InvalidHandle {
		_ = windows.CloseHandle(l.next)
		l.next = windows.InvalidHandle
	}
	l.mu.Unlock()
	l.accepting.Wait()
	return windows.CloseHandle(l.closeEv)
}

// pipeConn is a connected pipe instance doing its own overlapped I/O, so a
// Read and a Write can run at once (an *os.File needs the caller to
// serialise them) and Close cancels both.
type pipeConn struct {
	h       windows.Handle
	closeEv windows.Handle

	mu      sync.Mutex
	closed  bool
	pending sync.WaitGroup
}

func newPipeConn(h windows.Handle) (*pipeConn, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return &pipeConn{h: h, closeEv: ev}, nil
}

// begin registers an operation, or reports that the conn is closed.
func (c *pipeConn) begin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.pending.Add(1)
	return true
}

// do runs one overlapped operation and waits for it or for Close.
func (c *pipeConn) do(op func(*windows.Overlapped) error) (int, error) {
	if !c.begin() {
		return 0, ErrClosed
	}
	defer c.pending.Done()
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := windows.Overlapped{HEvent: ev}
	if err := op(&ov); err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, pipeErr(err)
	}
	which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, c.closeEv}, false, windows.INFINITE)
	if err != nil {
		return 0, err
	}
	var n uint32
	if which != windows.WAIT_OBJECT_0 {
		_ = windows.CancelIoEx(c.h, &ov)
		_ = windows.GetOverlappedResult(c.h, &ov, &n, true)
		return 0, ErrClosed
	}
	if err := windows.GetOverlappedResult(c.h, &ov, &n, false); err != nil {
		return int(n), pipeErr(err)
	}
	return int(n), nil
}

func pipeErr(err error) error {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) || errors.Is(err, windows.ERROR_NO_DATA) {
		return io.EOF
	}
	return err
}

func (c *pipeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.do(func(ov *windows.Overlapped) error {
		var done uint32 // x/sys writes through it even for overlapped I/O
		return windows.ReadFile(c.h, p, &done, ov)
	})
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func (c *pipeConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		chunk := p[written:]
		n, err := c.do(func(ov *windows.Overlapped) error {
			var done uint32
			return windows.WriteFile(c.h, chunk, &done, ov)
		})
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Close cancels pending I/O, waits for it, and closes the handle.
func (c *pipeConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	_ = windows.SetEvent(c.closeEv)
	c.pending.Wait()
	err := windows.CloseHandle(c.h)
	_ = windows.CloseHandle(c.closeEv)
	return err
}

// Dial connects to the service's pipe. It asks the server for identification
// only (SECURITY_IDENTIFICATION), so a pipe squatter can't impersonate the
// helper's user.
func Dial(ctx context.Context, addr string) (Conn, error) {
	name, err := windows.UTF16PtrFromString(addr)
	if err != nil {
		return nil, err
	}
	for {
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return newPipeConn(h)
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("ipc: dial %s: %w", addr, err)
		}
		select { // every instance busy: try again shortly
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// PeerIdentity returns the identity of the process on the other end of a
// server-side connection: user and SID from its token, its session id.
func PeerIdentity(c Conn) (Identity, error) {
	pc, ok := c.(*pipeConn)
	if !ok {
		return Identity{}, errors.New("ipc: not a pipe connection")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pc.h, &pid); err != nil {
		return Identity{}, fmt.Errorf("ipc: client pid: %w", err)
	}
	return processIdentity(pid)
}

// ServerIdentity returns the owner of the pipe, for a helper to check it is
// talking to the agent and not a squatter. It reads the owner from the pipe
// handle rather than the server process: a user can't query a SYSTEM
// process, but can read the pipe's owner (GENERIC_READ includes
// READ_CONTROL). Only SYSTEM or Administrators can create a pipe they own,
// and FILE_FLAG_FIRST_PIPE_INSTANCE stops anyone else taking the name.
// PID is the server's, for logging only.
func ServerIdentity(c Conn) (Identity, error) {
	pc, ok := c.(*pipeConn)
	if !ok {
		return Identity{}, errors.New("ipc: not a pipe connection")
	}
	var id Identity
	var pid uint32
	if windows.GetNamedPipeServerProcessId(pc.h, &pid) == nil {
		id.PID = int(pid)
	}
	sd, err := windows.GetSecurityInfo(pc.h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return id, fmt.Errorf("ipc: pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return id, fmt.Errorf("ipc: pipe has no owner: %v", err)
	}
	setAccount(&id, owner)
	return id, nil
}

// setAccount fills id's UID and User from sid.
func setAccount(id *Identity, sid *windows.SID) {
	id.UID = sid.String()
	id.User = id.UID
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		id.User = domain + `\` + account
	}
}

func processIdentity(pid uint32) (Identity, error) {
	id := Identity{PID: int(pid)}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		return id, fmt.Errorf("ipc: session of pid %d: %w", pid, err)
	}
	id.SessionID = strconv.FormatUint(uint64(session), 10)

	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return id, fmt.Errorf("ipc: open pid %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(p) }()
	var buf [windows.MAX_LONG_PATH]uint16
	n := uint32(windows.MAX_LONG_PATH)
	if windows.QueryFullProcessImageName(p, 0, &buf[0], &n) == nil {
		id.Exe = windows.UTF16ToString(buf[:n])
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return id, fmt.Errorf("ipc: token of pid %d: %w", pid, err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return id, fmt.Errorf("ipc: token user: %w", err)
	}
	setAccount(&id, tu.User.Sid)
	return id, nil
}

// privilegedSIDs may run the service: LocalSystem and Administrators.
var privilegedSIDs = map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}

// IsPrivileged reports whether id is the account the service runs as.
func IsPrivileged(id Identity) bool { return privilegedSIDs[id.UID] }

// SameUser reports whether id is the user running this process.
func SameUser(id Identity) bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.String() == id.UID
}
