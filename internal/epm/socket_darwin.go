//go:build darwin

package epm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"sentinelgo/internal/epm/svcparse"
)

// SocketPath is the Unix Domain Socket path the user-space EPM client
// (cmd/sentinelgo-epm) connects to.
const SocketPath = "/var/run/sentinelgo/epm.sock"

// requestTimeout bounds how long a single connection may take end to end
// (hash + codesign + policy + launch), so a stuck client or a hung subprocess
// cannot leak a goroutine/fd forever.
const requestTimeout = 30 * time.Second

// socketRequest is the wire shape a client sends: which application it wants
// elevated, and any extra arguments (whitespace-split; no shell-quoting
// support — a Phase 2 simplification, see splitArgs). The server never
// trusts a client-supplied user identity — it authenticates the connection
// itself via SO_PEERCRED-equivalent (LOCAL_PEERCRED) and only proceeds if the
// peer is the console user, so a compromised or lying client cannot claim to
// be a different user.
type socketRequest struct {
	RequestID   string `json:"request_id"`
	AppPath     string `json:"app_path"`
	CommandLine string `json:"command_line"`
	// ScriptPath, when non-empty, is a script/installer payload to run via the
	// interpreter named by AppPath; the server computes its hash itself (see
	// evaluateAndLaunch) rather than trusting a client-supplied value.
	ScriptPath string `json:"script_path,omitempty"`
	// Args is the argument string the script is being invoked with.
	Args string `json:"args,omitempty"`
}

// socketResponse is the wire shape returned to the client.
type socketResponse struct {
	RequestID string `json:"request_id"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProcessID uint32 `json:"process_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SocketServer is the macOS enforcement transport: it accepts elevation
// requests from the unprivileged user-space client over a Unix Domain
// Socket, verifies the connecting peer is the console user, evaluates
// policy, and — if allowed — launches the target process in that user's GUI
// session.
type SocketServer struct {
	rules   RuleProvider
	auditor *Auditor

	listener net.Listener
}

// NewSocketServer builds a SocketServer. rules supplies the live policy rule
// set (queried fresh per request) and auditor records every decision.
func NewSocketServer(rules RuleProvider, auditor *Auditor) *SocketServer {
	return &SocketServer{rules: rules, auditor: auditor}
}

// Serve runs the accept loop until ctx is cancelled or Stop is called. Each
// connection is handled in its own goroutine.
func (s *SocketServer) Serve(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	// Remove a stale socket left behind by a previous, uncleanly-stopped run;
	// net.Listen would otherwise fail with "address already in use".
	if err := os.Remove(SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", SocketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", SocketPath, err)
	}
	// The client runs as the unprivileged console user, so the socket file
	// itself must be connectable by everyone; the actual authorization
	// decision happens per-connection via peer-UID verification against the
	// console user, not via filesystem permissions.
	if err := os.Chmod(SocketPath, 0666); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.listener = ln

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("epm: accept: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// Stop closes the listener, unblocking any pending Accept.
func (s *SocketServer) Stop() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *SocketServer) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		log.Printf("epm: unexpected connection type %T", conn)
		return
	}

	peerUID, err := peerCredUID(unixConn)
	if err != nil {
		log.Printf("epm: resolve peer credentials: %v", err)
		return
	}

	consoleUID, consoleUsername, err := ConsoleUser()
	if err != nil {
		log.Printf("epm: resolve console user: %v", err)
		return
	}
	if peerUID != consoleUID {
		log.Printf("epm: rejecting connection from uid %d (does not match console user uid %d)", peerUID, consoleUID)
		return
	}

	var req socketRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("epm: decode request: %v", err)
		return
	}
	if req.RequestID == "" {
		req.RequestID = uuid.NewString()
	}

	resp := s.evaluateAndLaunch(req, peerUID, consoleUsername)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("epm: encode response: %v", err)
	}
}

// evaluateAndLaunch resolves the application's identity, evaluates policy,
// and — if allowed — performs the elevated launch. userID (the resolved
// console username) and uid (its numeric UID, already verified to match the
// connecting peer) come from the server's own OS-level resolution, never
// from req.
func (s *SocketServer) evaluateAndLaunch(req socketRequest, uid uint32, userID string) socketResponse {
	resp := socketResponse{RequestID: req.RequestID}

	appHash, err := ComputeFileHash(req.AppPath)
	if err != nil {
		resp.Error = fmt.Sprintf("hash application: %v", err)
		return resp
	}
	// Publisher is best-effort: an unsigned binary just can't match
	// publisher-based rules, it isn't a hard failure of the request.
	publisher, _ := VerifyCodeSignature(req.AppPath)

	// The script's hash is always computed server-side from the file on disk
	// — a client-supplied hash would let a compromised client substitute a
	// different payload after the policy check.
	var scriptHash string
	if req.ScriptPath != "" {
		var hashErr error
		scriptHash, hashErr = ComputeFileHash(req.ScriptPath)
		if hashErr != nil {
			resp.Error = fmt.Sprintf("hash script: %v", hashErr)
			return resp
		}
	}
	serviceName, _ := svcparse.ExtractServiceName(req.AppPath, req.CommandLine)

	rules, err := s.rules.GetRules()
	if err != nil {
		resp.Error = fmt.Sprintf("load policy rules: %v", err)
		return resp
	}

	elevReq := ElevationRequest{
		RequestID:            req.RequestID,
		UserID:               userID,
		AppPath:              req.AppPath,
		AppHash:              appHash,
		Publisher:            publisher,
		Now:                  time.Now().UTC(),
		ScriptPath:           req.ScriptPath,
		ScriptHash:           scriptHash,
		ActualArgs:           req.Args,
		RequestedServiceName: serviceName,
	}
	decision := NewEngine(rules).Evaluate(elevReq)

	resp.Allowed = decision.Allowed
	resp.Reason = decision.Reason

	if decision.Allowed {
		// req.AppPath is always the interpreter/executable to launch. When a
		// script is requested, it must be launched as its own argv[0]-following
		// argument ("interpreter <scriptPath> [args]"), not folded into
		// CommandLine — so it's prepended onto the launch args slice here.
		launchArgs := splitArgs(req.CommandLine)
		if req.ScriptPath != "" {
			launchArgs = append([]string{req.ScriptPath}, splitArgs(req.Args)...)
		}
		if result, launchErr := LaunchAsUser(uid, req.AppPath, launchArgs); launchErr != nil {
			resp.Allowed = false
			resp.Error = fmt.Sprintf("launch failed: %v", launchErr)
		} else {
			resp.ProcessID = result.ProcessID
		}
	}

	s.audit(elevReq, decision)
	return resp
}

func (s *SocketServer) audit(req ElevationRequest, decision ElevationResponse) {
	if s.auditor == nil {
		return
	}
	entry := AuditEntry{
		RequestID:   req.RequestID,
		UserID:      req.UserID,
		AppPath:     req.AppPath,
		AppHash:     req.AppHash,
		Decision:    DecisionDeny,
		PolicyID:    decision.PolicyID,
		LaunchedAt:  req.Now,
		ScriptHash:  req.ScriptHash,
		ServiceName: req.RequestedServiceName,
	}
	if decision.Allowed {
		entry.Decision = DecisionAllow
	}
	if err := s.auditor.Log(entry); err != nil {
		log.Printf("epm: audit log failed: %v", err)
	}
}

// peerCredUID returns the UID of the process on the other end of conn, via
// the LOCAL_PEERCRED socket option (Darwin's SO_PEERCRED equivalent). This is
// how the server authenticates a connection without trusting anything the
// client says about itself.
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

// splitArgs is defined in splitargs.go (no build tag) and handles
// single-quoted, double-quoted, and backslash-escaped arguments so that
// paths containing spaces survive the round-trip from the EPM client to
// the elevated process launcher.
