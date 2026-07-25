//go:build windows

package epm

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

// ElevationResult is the outcome of a client-submitted elevation request,
// exposed to callers of RequestElevation (cmd/sentinelgo-epm's user-space
// client) without leaking the pipe wire format.
type ElevationResult struct {
	Allowed   bool
	Reason    string
	ProcessID uint32
	Error     string
}

// RequestElevation connects to the EPM Named Pipe server as the current
// (unprivileged) user and submits a single elevation request for appPath,
// with optional extra arguments in commandLine. It blocks until the server
// responds or the connection fails.
//
// The server independently re-derives the caller's identity from the OS
// (the connecting process's session, via GetNamedPipeClientProcessId) rather
// than trusting anything this function sends, so there is no privilege
// implication in this function running unprivileged.
func RequestElevation(appPath, commandLine string) (*ElevationResult, error) {
	handle, err := dialPipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	req := pipeRequest{
		RequestID:   uuid.NewString(),
		AppPath:     appPath,
		CommandLine: commandLine,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var written uint32
	if err := windows.WriteFile(handle, data, &written, nil); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	buf := make([]byte, pipeBufferSize)
	var n uint32
	if err := windows.ReadFile(handle, buf, &n, nil); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp pipeResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &ElevationResult{
		Allowed:   resp.Allowed,
		Reason:    resp.Reason,
		ProcessID: resp.ProcessID,
		Error:     resp.Error,
	}, nil
}

func dialPipe() (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return 0, fmt.Errorf("convert pipe name: %w", err)
	}

	handle, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,   // no sharing: this is a private one-to-one channel
		nil, // default security attributes
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("connect to %s (is the agent running with EPM enabled?): %w", PipeName, err)
	}

	// The server uses message-type framing (PIPE_TYPE_MESSAGE); the client
	// must opt into message-read mode too, or ReadFile would instead return
	// raw byte-stream chunks.
	mode := uint32(windows.PIPE_READMODE_MESSAGE)
	if err := windows.SetNamedPipeHandleState(handle, &mode, nil, nil); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("set pipe read mode: %w", err)
	}

	return handle, nil
}
