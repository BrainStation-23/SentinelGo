// Package ipc is the protocol between the service and the session helpers:
// length-prefixed JSON frames over a named pipe (Windows) or a Unix socket
// (macOS, Linux). Each frame is a 4-byte big-endian length followed by a JSON
// Message. Frames are bounded per direction, and an oversized or malformed
// frame closes the connection.
//
// The service takes the user identity in events from the peer's OS
// credentials (PeerIdentity), never from message fields.
package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"sentinelgo/internal/dlp/events"
)

// Proto is the protocol version. A peer speaking another version is
// disconnected.
const Proto = 1

// Frame limits. Helpers send small messages; the service sends whole policy
// bundles.
const (
	MaxHelperFrame  = 256 << 10     // helper → service
	MaxServiceFrame = 2 * (8 << 20) // service → helper: a bundle (8 MB cap) plus room for re-encoding
)

// Message types.
const (
	TypeHello  = "hello"  // helper → service, first frame
	TypePolicy = "policy" // service → helper
	TypeEvent  = "event"  // helper → service
	TypeStatus = "status" // helper → service
	TypePing   = "ping"   // either way
	TypeStop   = "stop"   // service → helper: exit
)

// ErrFrameTooLarge is returned for a frame over the reader's limit.
var ErrFrameTooLarge = errors.New("ipc: frame too large")

// Message is one frame. Exactly the field matching Type is set.
type Message struct {
	Proto  int             `json:"proto"`
	Type   string          `json:"type"`
	Hello  *Hello          `json:"hello,omitempty"`
	Policy json.RawMessage `json:"policy,omitempty"` // the bundle, as the server sent it
	Event  *events.Event   `json:"event,omitempty"`
	Status *Status         `json:"status,omitempty"`
}

// Hello introduces a helper. PID is informational: the service reads the
// peer's identity from the OS.
type Hello struct {
	PID          int               `json:"pid"`
	Version      string            `json:"version"`
	Capabilities map[string]string `json:"capabilities"`
}

// Status is a helper's state report.
type Status struct {
	State        string            `json:"state"` // e.g. "running", "idle"
	Capabilities map[string]string `json:"capabilities,omitempty"`
}

// Write sends m as one frame.
func Write(w io.Writer, m Message) error {
	m.Proto = Proto
	// No HTML escaping: it would grow a bundle full of "<" six-fold and push
	// a valid policy over the reader's frame limit.
	var enc bytes.Buffer
	e := json.NewEncoder(&enc)
	e.SetEscapeHTML(false)
	if err := e.Encode(m); err != nil {
		return fmt.Errorf("ipc: encode %s: %w", m.Type, err)
	}
	data := bytes.TrimSuffix(enc.Bytes(), []byte("\n"))
	if len(data) > MaxServiceFrame {
		return fmt.Errorf("%w: %s is %d bytes", ErrFrameTooLarge, m.Type, len(data))
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data))) // #nosec G115 -- a message is far below 4 GiB
	copy(buf[4:], data)
	_, err := w.Write(buf)
	return err
}

// Read reads one frame of at most limit bytes. An oversized frame, a frame of
// another protocol version or one without a type is an error; the caller
// closes the connection.
func Read(r io.Reader, limit int) (Message, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int64(n) > int64(limit) {
		return Message{}, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, n, limit)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return Message{}, fmt.Errorf("ipc: decode frame: %w", err)
	}
	if m.Proto != Proto {
		return Message{}, fmt.Errorf("ipc: protocol %d, want %d", m.Proto, Proto)
	}
	if m.Type == "" {
		return Message{}, errors.New("ipc: frame without a type")
	}
	return m, nil
}

// Identity is who is on the other end of a connection, from the OS.
type Identity struct {
	User      string // DOMAIN\user on Windows, the user name on Unix
	UID       string // SID on Windows, numeric uid on Unix
	PID       int
	SessionID string // Windows session id; the uid on Unix
	Exe       string // the peer's executable; "" if it couldn't be read
}

// SameExecutable reports whether id runs this process's own executable. The
// service only takes events from its own binary's `dlp-session`, not from any
// local program that connects.
func SameExecutable(id Identity) bool {
	self, err := os.Executable()
	if err != nil || id.Exe == "" {
		return false
	}
	return samePath(resolve(self), resolve(id.Exe))
}

func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// samePath compares paths, case-insensitively on Windows.
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Conn is one end of a service↔helper connection.
type Conn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Listener accepts helper connections.
type Listener interface {
	Accept() (Conn, error)
	Close() error
}

// TrustedServer reports whether a helper may take policy from a server with
// identity id: the service account, or the helper's own user (who can only
// fool themselves). Any other user is a squatter.
func TrustedServer(id Identity) bool {
	return IsPrivileged(id) || SameUser(id)
}
