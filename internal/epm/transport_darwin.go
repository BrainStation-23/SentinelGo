//go:build darwin

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

// darwinTransport implements Transport over a Unix Domain Socket. It is the
// Phase 2 home of what socket_darwin.go's SocketServer used to do directly —
// see socket_darwin.go for the thin SocketServer wrapper that keeps the
// pre-Phase-2 public API.
type darwinTransport struct {
	listener *net.UnixListener
}

func newDarwinTransport() *darwinTransport { return &darwinTransport{} }

func (t *darwinTransport) Listen(ctx context.Context) error {
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

// Accept blocks until a client connects, then authenticates it: LOCAL_PEERCRED
// gives the kernel-verified UID of the connecting process, cross-checked
// against the single active console user — macOS has no logind analogue, so
// unlike Linux this only ever accepts the one console session, not any
// interactive session.
func (t *darwinTransport) Accept(ctx context.Context) (Conn, error) {
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

	peerUID, err := peerCredUID(unixRawConn)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("resolve peer credentials: %w", err)
	}

	consoleUID, consoleUsername, err := ConsoleUser()
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("resolve console user: %w", err)
	}
	if peerUID != consoleUID {
		_ = rawConn.Close()
		return nil, fmt.Errorf("peer uid %d does not match console user uid %d", peerUID, consoleUID)
	}

	return newUnixConn(rawConn, PeerIdentity{
		UID: peerUID, UserID: consoleUsername,
	}), nil
}

func (t *darwinTransport) Addr() string { return SocketPath }

func (t *darwinTransport) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

// peerCredUID returns the UID of the process on the other end of conn, via
// the LOCAL_PEERCRED socket option (Darwin's SO_PEERCRED equivalent).
func peerCredUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("SyscallConn: %w", err)
	}

	var uid uint32
	var credErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("SyscallConn.Control: %w", ctrlErr)
	}
	if credErr != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", credErr)
	}
	return uid, nil
}

// darwinIdentifier implements Identifier for the Darwin transport.
type darwinIdentifier struct{}

func (darwinIdentifier) Groups(PeerIdentity) ([]string, error) { return nil, nil }
func (darwinIdentifier) Publisher(path string) (string, error) { return verifyCodeSignatureFn(path) }

// darwinLauncher implements Launcher for the Darwin transport.
type darwinLauncher struct{}

func (darwinLauncher) Launch(peer PeerIdentity, spec LaunchSpec) (*Launched, error) {
	launchArgs := splitArgs(spec.CommandLine)
	if spec.ScriptPath != "" {
		launchArgs = append([]string{spec.ScriptPath}, splitArgs(spec.ScriptArgs)...)
	}
	result, err := launchAsUserFn(peer.UID, spec.AppPath, launchArgs)
	if err != nil {
		return nil, err
	}
	return &Launched{ProcessID: result.ProcessID}, nil
}

// Seams — new for Darwin in Phase 2 (socket_darwin.go called ComputeFileHash/
// VerifyCodeSignature/LaunchAsUser directly pre-Phase-2, with no seam at
// all): package-level function vars so tests can control hashing/publisher/
// launch without touching real OS state, matching the pattern Windows already
// had (launcher_iface_windows.go). Named distinctly from VerifyCodeSignature
// itself (verifyCodeSignatureFn, not verifyPackageSignatureFn as on Linux)
// since the two files never compile together but share this package's
// namespace with each other's declarations only via build-tag exclusion, not
// scoping — a same-named var on both would still be fine, but distinct names
// here read more clearly against codesign_darwin.go's actual function name.
var (
	computeFileHashFn     = ComputeFileHash
	verifyCodeSignatureFn = VerifyCodeSignature
	launchAsUserFn        = LaunchAsUser
)
