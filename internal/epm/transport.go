package epm

import (
	"context"
	"time"
)

// This file has no build tag: it declares the seam Phase 2 introduces to
// de-duplicate what were three independent copies of the same
// evaluate-hash-verify-launch-audit logic (pipe_windows.go, socket_linux.go,
// socket_darwin.go). server.go holds the one remaining copy of that logic;
// each platform supplies a Transport/Conn (framing + peer identity) and a
// Launcher (the privileged launch primitive), both of which already exist in
// this package today — transport_windows.go/transport_unix.go and
// launcher_iface_windows.go/launcher_iface_unix.go wrap them, they do not
// reimplement them.

// PeerIdentity is the OS-authenticated identity of the process on the other
// end of a connection. Every field is derived by the platform Transport from
// the OS itself at Accept time — never from anything the client sent — and
// stays valid for the life of that connection, which is why a connection may
// carry more than one message (protocol v2's prompt round trip) without
// re-authenticating.
type PeerIdentity struct {
	PID       uint32
	SessionID uint32 // Windows WTS session ID; Linux logind session (numeric); 0 on Darwin
	UID       uint32 // Unix UID; 0 on Windows
	UserID    string // "DOMAIN\user" (Windows) or username (Unix)
	Groups    []string
	// Cred is the opaque platform credential the Launcher needs to actually
	// perform a privileged launch — a windows.Token on Windows, unused
	// (nil) on Unix, where the daemon's own root/uid=0 identity plus
	// PeerIdentity.UID is sufficient. Declared as `any` so this file stays
	// buildable on every platform without importing golang.org/x/sys/windows.
	// Never serialized, never crosses the wire.
	Cred any
}

// Conn is one accepted client connection. ReadMessage/WriteMessage exchange
// whole messages; the platform implementation owns framing, which is exactly
// why neither existing wire format has to change: the Windows implementation
// keeps PIPE_TYPE_MESSAGE (one WriteFile == one ReadFile, no length prefix)
// and the Unix implementation keeps streaming newline-delimited JSON.
type Conn interface {
	Peer() PeerIdentity
	ReadMessage() ([]byte, error)
	WriteMessage(msg []byte) error
	SetDeadline(t time.Time) error
	Close() error
}

// Transport is a platform listener: bind, accept connections, and stop.
type Transport interface {
	Listen(ctx context.Context) error
	Accept(ctx context.Context) (Conn, error)
	Addr() string
	Close() error
}

// LaunchSpec is the platform-neutral description of what to start, built by
// Server.elevate from an ElevateBody after policy has already allowed it.
// CommandLine and ScriptArgs are carried as raw strings, exactly as they
// arrived on the wire — splitting them into an argv array is a Unix-only
// launcher concern (see splitArgs in splitargs.go); the Windows launcher
// needs the raw string verbatim, since CreateProcessAsUser takes a single
// command-line string, not an argv array.
type LaunchSpec struct {
	AppPath string
	// CommandLine is the extra-argument string for a direct (non-script)
	// launch — the interpreter/executable's own arguments.
	CommandLine string
	ScriptPath  string
	// ScriptArgs is the argument string a script/installer payload is
	// invoked with, meaningful only when ScriptPath is set.
	ScriptArgs  string
	WorkingDir  string
	Constraints Constraints
}

// Launched identifies the process a Launcher started.
type Launched struct {
	ProcessID uint32
	// TrackedPID differs from ProcessID on macOS, where launchctl asuser execs
	// the target as a grandchild — see launcher_darwin.go. Zero means unknown;
	// callers fall back to ProcessID.
	TrackedPID uint32
	StartedAt  time.Time
}

// Launcher performs the privileged launch after policy has already allowed
// it. Implementations MUST perform no policy checks themselves — Server is
// the only caller and only calls Launch after Engine.Evaluate returned
// Allowed.
type Launcher interface {
	Launch(peer PeerIdentity, spec LaunchSpec) (*Launched, error)
}

// Identifier resolves platform facts about a peer or a file that the policy
// engine's Extract functions need but a Transport alone cannot supply.
type Identifier interface {
	// Groups resolves peer's group memberships, for CondUserGroup. No
	// current implementation populates this (see userGroupMatcher's doc
	// comment) — callers may return (nil, nil) rather than an error.
	Groups(peer PeerIdentity) ([]string, error)
	// Publisher verifies path's code signature / package provenance,
	// wrapping VerifyAuthenticode (Windows), VerifyCodeSignature (Darwin), or
	// VerifyPackageSignature (Linux). An error means "no publisher identity
	// available" (unsigned, or verification failed) — not a fatal condition.
	Publisher(path string) (string, error)
}
