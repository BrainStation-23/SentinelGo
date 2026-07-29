//go:build linux || darwin

package epm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// This file holds what is genuinely identical between the Linux and Darwin
// Unix Domain Socket transports: message framing and the listener bootstrap.
// Peer-credential resolution differs enough between the two (Linux's
// SO_PEERCRED yields (uid, pid) in one call and is checked against
// SessionForPID, allowing any interactive session; Darwin's LOCAL_PEERCRED
// yields only uid and is checked against the single active ConsoleUser) that
// Listen/Accept themselves stay in transport_linux.go/transport_darwin.go —
// see those files' Accept for the platform-specific identity step this
// bootstrap and unixConn are shared underneath.

// unixSocketRequestTimeout bounds how long a single connection may take end
// to end (hash + verify + policy + launch), so a stuck client or a hung
// subprocess cannot leak a goroutine/fd forever. Unchanged in value from the
// pre-Phase-2 requestTimeout constant both socket_linux.go and
// socket_darwin.go declared independently.
const unixSocketRequestTimeout = 30 * time.Second

// bootstrapUnixSocket creates the socket directory, removes a stale socket
// left behind by a previous, uncleanly-stopped run (net.Listen would
// otherwise fail with "address already in use"), listens, and chmods the
// socket file to 0666 — the client runs as the unprivileged console user, so
// the socket itself must be connectable by everyone; the actual authorization
// decision happens per-connection via peer-identity verification, not
// filesystem permissions. Identical to what socket_linux.go's and
// socket_darwin.go's Serve each did independently pre-Phase-2.
func bootstrapUnixSocket(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln.(*net.UnixListener), nil
}

// unixConn wraps one accepted Unix Domain Socket connection. ReadMessage
// keeps one *json.Decoder bound to the connection and decodes into a
// json.RawMessage — that consumes exactly one JSON value from the stream and
// hands back its exact raw bytes, precisely "one message" with zero change to
// the pre-Phase-2 streaming-JSON wire format (json.NewDecoder(conn).Decode).
// WriteMessage appends '\n', matching json.NewEncoder's own behavior exactly.
type unixConn struct {
	conn net.Conn
	peer PeerIdentity
	dec  *json.Decoder
}

func newUnixConn(conn net.Conn, peer PeerIdentity) *unixConn {
	return &unixConn{conn: conn, peer: peer, dec: json.NewDecoder(conn)}
}

func (c *unixConn) Peer() PeerIdentity { return c.peer }

func (c *unixConn) ReadMessage() ([]byte, error) {
	var raw json.RawMessage
	if err := c.dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	return raw, nil
}

func (c *unixConn) WriteMessage(msg []byte) error {
	if _, err := c.conn.Write(append(msg, '\n')); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func (c *unixConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *unixConn) Close() error                  { return c.conn.Close() }
