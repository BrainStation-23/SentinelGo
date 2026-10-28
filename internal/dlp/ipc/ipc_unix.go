//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// DefaultAddress is the service's socket. Its directory is root-owned 0755;
// the socket is 0666 so every user's helper can connect, and the service
// identifies each peer by its credentials.
const DefaultAddress = "/var/run/sentinelgo/dlp.sock"

// ErrClosed is returned by Accept after Close.
var ErrClosed = net.ErrClosed

type unixListener struct{ l *net.UnixListener }

// Listen creates the socket, replacing a stale one.
func Listen(addr string) (Listener, error) {
	if err := secureSocketDir(filepath.Dir(addr)); err != nil {
		return nil, err
	}
	if err := os.Remove(addr); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", addr, err)
	}
	if err := os.Chmod(addr, 0o666); err != nil { // #nosec G302 -- any local user's helper connects; peers are identified by SO_PEERCRED
		_ = l.Close()
		return nil, fmt.Errorf("ipc: socket mode: %w", err)
	}
	return unixListener{l: l}, nil
}

// secureSocketDir creates dir 0755 if needed and refuses one another user
// owns or others can write to: its owner could replace the socket and pose
// as the service to helpers.
func secureSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- helpers of every user must reach the socket
		return fmt.Errorf("ipc: socket dir: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("ipc: socket dir: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("ipc: socket dir %s is not a directory", dir)
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("ipc: socket dir %s is not owned by this account; refusing it", dir)
	case fi.Mode().Perm()&0o022 != 0:
		if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- readable by all helpers, writable by the service only
			return fmt.Errorf("ipc: socket dir %s is writable by others: %w", dir, err)
		}
	}
	return nil
}

func (u unixListener) Accept() (Conn, error) {
	c, err := u.l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (u unixListener) Close() error { return u.l.Close() }

// Dial connects to the service's socket.
func Dial(ctx context.Context, addr string) (Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", addr)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial %s: %w", addr, err)
	}
	return c, nil
}

// PeerIdentity returns the identity of the process on the other end, from
// the socket's peer credentials.
func PeerIdentity(c Conn) (Identity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Identity{}, errors.New("ipc: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Identity{}, err
	}
	var uid, pid int
	var credErr error
	if err := raw.Control(func(fd uintptr) { uid, pid, credErr = peerCred(int(fd)) }); err != nil {
		return Identity{}, err
	}
	if credErr != nil {
		return Identity{}, fmt.Errorf("ipc: peer credentials: %w", credErr)
	}
	id := Identity{UID: strconv.Itoa(uid), PID: pid, SessionID: strconv.Itoa(uid), Exe: processExe(pid)}
	id.User = id.UID
	if u, err := user.LookupId(id.UID); err == nil {
		id.User = u.Username
	}
	return id, nil
}

// ServerIdentity is PeerIdentity seen from the helper's side.
func ServerIdentity(c Conn) (Identity, error) { return PeerIdentity(c) }

// IsPrivileged reports whether id is root, which the service runs as.
func IsPrivileged(id Identity) bool { return id.UID == "0" }

// SameUser reports whether id is the user running this process.
func SameUser(id Identity) bool { return id.UID == strconv.Itoa(os.Getuid()) }
