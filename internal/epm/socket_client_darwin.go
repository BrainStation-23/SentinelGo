//go:build darwin

package epm

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
)

// ElevationResult is the outcome of a client-submitted elevation request,
// exposed to callers of RequestElevation (cmd/sentinelgo-epm's user-space
// client) without leaking the socket wire format.
type ElevationResult struct {
	Allowed   bool
	Reason    string
	ProcessID uint32
	Error     string
}

// RequestElevation connects to the EPM Unix Domain Socket server as the
// current (unprivileged) user and submits a single elevation request for
// appPath. It blocks until the server responds or the connection fails.
//
// When scriptPath is "", this is a direct binary elevation request and
// commandLine carries appPath's own extra arguments (existing behavior).
// When scriptPath is non-empty, appPath is the interpreter to run scriptPath
// through, and commandLine is instead interpreted as the script's own
// arguments.
//
// The server independently re-derives the caller's identity from the OS
// (LOCAL_PEERCRED on the accepted connection, checked against the console
// user) rather than trusting anything this function sends, so there is no
// privilege implication in this function running unprivileged.
//
// Sends a v1-shaped request (no protocol_version/op set) — see protocol.go's
// Envelope doc comment — so this client keeps working unmodified against
// both a pre-Phase-2 server and the current one; Phase 5 is what upgrades
// this client to speak v2.
func RequestElevation(appPath, commandLine, scriptPath string) (*ElevationResult, error) {
	conn, err := net.DialTimeout("unix", SocketPath, unixSocketRequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s (is the agent running with EPM enabled?): %w", SocketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(unixSocketRequestTimeout))

	env := Envelope{
		RequestID: uuid.NewString(),
		AppPath:   appPath,
	}
	if scriptPath != "" {
		env.ScriptPath = scriptPath
		env.Args = commandLine
	} else {
		env.CommandLine = commandLine
	}
	if err := json.NewEncoder(conn).Encode(env); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return &ElevationResult{
		Allowed:   resp.Allowed,
		Reason:    resp.Reason,
		ProcessID: resp.ProcessID,
		Error:     resp.Error,
	}, nil
}
