//go:build linux

package epm

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SocketPath is the Unix Domain Socket path the user-space EPM client
// (cmd/sentinelgo-epm) connects to.
const SocketPath = "/var/run/sentinelgo/epm.sock"

// linuxTransport implements Transport over a Unix Domain Socket. It is the
// Phase 2 home of what socket_linux.go's SocketServer used to do directly —
// see socket_linux.go for the thin SocketServer wrapper that keeps the
// pre-Phase-2 public API (NewSocketServer, .Serve, .Stop) working.
type linuxTransport struct {
	listener *net.UnixListener
}

func newLinuxTransport() *linuxTransport { return &linuxTransport{} }

func (t *linuxTransport) Listen(ctx context.Context) error {
	ln, err := bootstrapUnixSocket(SocketPath)
	if err != nil {
		return err
	}
	t.listener = ln
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return nil
}

// Accept blocks until a client connects, then authenticates it: SO_PEERCRED
// gives the kernel-verified (uid, pid) of the connecting process, and that
// process's own systemd-logind session is independently resolved and cross-
// checked against it — a mismatch means something is inconsistent enough not
// to trust. Resolving the connecting process's own session (rather than
// requiring it to be "the" active/focused session) is what lets a second
// concurrent login use EPM too, matching Windows' per-client-session model.
func (t *linuxTransport) Accept(ctx context.Context) (Conn, error) {
	rawConn, err := t.listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("accept: %w", err)
	}
	unixRawConn, ok := rawConn.(*net.UnixConn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("unexpected connection type %T", rawConn)
	}

	peerUID, peerPID, err := peerCredentials(unixRawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("resolve peer credentials: %w", err)
	}

	sessionUID, sessionUsername, err := SessionForPID(peerPID)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("resolve session for pid %d: %w", peerPID, err)
	}
	if sessionUID != peerUID {
		_ = rawConn.Close()
		return nil, fmt.Errorf("peer uid %d does not match session uid %d", peerUID, sessionUID)
	}

	return newUnixConn(rawConn, PeerIdentity{
		PID: peerPID, UID: peerUID, UserID: sessionUsername,
	}), nil
}

func (t *linuxTransport) Addr() string { return SocketPath }

func (t *linuxTransport) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

// peerCredentials returns the UID and PID of the process on the other end of
// conn, via the SO_PEERCRED socket option — how the server authenticates a
// connection without trusting anything the client says about itself.
func peerCredentials(conn *net.UnixConn) (uid uint32, pid uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("SyscallConn: %w", err)
	}

	var credErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
		pid = uint32(cred.Pid)
	})
	if ctrlErr != nil {
		return 0, 0, fmt.Errorf("SyscallConn.Control: %w", ctrlErr)
	}
	if credErr != nil {
		return 0, 0, fmt.Errorf("getsockopt SO_PEERCRED: %w", credErr)
	}
	return uid, pid, nil
}

// linuxIdentifier implements Identifier for the Linux transport.
type linuxIdentifier struct{}

func (linuxIdentifier) Groups(PeerIdentity) ([]string, error) { return nil, nil }
func (linuxIdentifier) Publisher(path string) (string, error) { return verifyPackageSignatureFn(path) }

// linuxLauncher implements Launcher for the Linux transport.
type linuxLauncher struct{}

func (linuxLauncher) Launch(peer PeerIdentity, spec LaunchSpec) (*Launched, error) {
	launchArgs := splitArgs(spec.CommandLine)
	if spec.ScriptPath != "" {
		launchArgs = append([]string{spec.ScriptPath}, splitArgs(spec.ScriptArgs)...)
	}
	result, err := launchAsUserFn(peer.UID, peer.UserID, spec.AppPath, launchArgs)
	if err != nil {
		return nil, err
	}
	return &Launched{ProcessID: result.ProcessID}, nil
}

// Seams — new for Linux in Phase 2 (socket_linux.go called ComputeFileHash/
// VerifyPackageSignature/LaunchAsUser directly pre-Phase-2, with no seam at
// all): package-level function vars so tests can control hashing/publisher/
// launch without touching real OS state, matching the pattern Windows already
// had (launcher_iface_windows.go). Named identically to Windows' seams —
// safe, since the two files never compile together.
var (
	computeFileHashFn        = ComputeFileHash
	verifyPackageSignatureFn = VerifyPackageSignature
	launchAsUserFn           = LaunchAsUser
)
