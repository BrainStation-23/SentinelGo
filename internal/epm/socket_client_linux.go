//go:build linux

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
// appPath, with optional extra arguments in commandLine. It blocks until the
// server responds or the connection fails.
//
// The server independently re-derives the caller's identity from the OS
// (SO_PEERCRED on the accepted connection, checked against the active
// console session) rather than trusting anything this function sends, so
// there is no privilege implication in this function running unprivileged.
func RequestElevation(appPath, commandLine string) (*ElevationResult, error) {
	conn, err := net.DialTimeout("unix", SocketPath, requestTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s (is the agent running with EPM enabled?): %w", SocketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	req := socketRequest{
		RequestID:   uuid.NewString(),
		AppPath:     appPath,
		CommandLine: commandLine,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp socketResponse
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
