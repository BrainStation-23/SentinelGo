//go:build linux

package epm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// SocketPath is the Unix Domain Socket path the user-space EPM client
// (cmd/sentinelgo-epm) connects to.
const SocketPath = "/var/run/sentinelgo/epm.sock"

// requestTimeout bounds how long a single connection may take end to end
// (hash + package verification + policy + launch), so a stuck client or a
// hung subprocess cannot leak a goroutine/fd forever.
const requestTimeout = 30 * time.Second

// socketRequest is the wire shape a client sends: which application it wants
// elevated, and any extra arguments (whitespace-split; no shell-quoting
// support — a simplification, see splitArgs). The server never trusts a
// client-supplied user identity — it authenticates the connection itself via
// SO_PEERCRED and only proceeds if the peer is the active console user, so a
// compromised or lying client cannot claim to be a different user.
type socketRequest struct {
	RequestID   string `json:"request_id"`
	AppPath     string `json:"app_path"`
	CommandLine string `json:"command_line"`
}

// socketResponse is the wire shape returned to the client.
type socketResponse struct {
	RequestID string `json:"request_id"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProcessID uint32 `json:"process_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SocketServer is the Linux enforcement transport: it accepts elevation
// requests from the unprivileged user-space client over a Unix Domain
// Socket, verifies the connecting peer is the active console user, evaluates
// policy, and — if allowed — launches the target process attached to that
// user's GUI session.
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

	peerUID, peerPID, err := peerCredentials(unixConn)
	if err != nil {
		log.Printf("epm: resolve peer credentials: %v", err)
		return
	}

	// Resolve the connecting process's own logind session rather than
	// requiring it to be "the" active/focused session — this is what makes a
	// second concurrent login (e.g. a background terminal, a non-focused
	// desktop) able to use EPM too, matching Windows' per-client-session
	// model in pipe_windows.go.
	sessionUID, sessionUsername, err := SessionForPID(peerPID)
	if err != nil {
		log.Printf("epm: resolve session for pid %d: %v", peerPID, err)
		return
	}
	if sessionUID != peerUID {
		// Defense in depth: the kernel-reported socket peer UID and the
		// UID logind recorded for that same process's session should always
		// agree. A mismatch means something is inconsistent enough to not
		// trust — reject rather than guess which one is right.
		log.Printf("epm: rejecting connection: peer uid %d does not match session uid %d", peerUID, sessionUID)
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

	resp := s.evaluateAndLaunch(req, peerUID, sessionUsername)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("epm: encode response: %v", err)
	}
}

// evaluateAndLaunch resolves the application's identity, evaluates policy,
// and — if allowed — performs the elevated launch. uid/userID (the console
// user's numeric UID and resolved username) come from the server's own
// OS-level resolution, already verified to match the connecting peer, never
// from req.
func (s *SocketServer) evaluateAndLaunch(req socketRequest, uid uint32, userID string) socketResponse {
	resp := socketResponse{RequestID: req.RequestID}

	appHash, err := ComputeFileHash(req.AppPath)
	if err != nil {
		resp.Error = fmt.Sprintf("hash application: %v", err)
		return resp
	}
	// Publisher is best-effort: a file not owned by a known package just
	// can't match publisher-based rules, it isn't a hard failure of the
	// request.
	publisher, _ := VerifyPackageSignature(req.AppPath)

	rules, err := s.rules.GetRules()
	if err != nil {
		resp.Error = fmt.Sprintf("load policy rules: %v", err)
		return resp
	}

	elevReq := ElevationRequest{
		RequestID: req.RequestID,
		UserID:    userID,
		AppPath:   req.AppPath,
		AppHash:   appHash,
		Publisher: publisher,
		Now:       time.Now().UTC(),
	}
	decision := NewEngine(rules).Evaluate(elevReq)

	resp.Allowed = decision.Allowed
	resp.Reason = decision.Reason

	if decision.Allowed {
		if result, launchErr := LaunchAsUser(uid, userID, req.AppPath, splitArgs(req.CommandLine)); launchErr != nil {
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
		RequestID:  req.RequestID,
		UserID:     req.UserID,
		AppPath:    req.AppPath,
		AppHash:    req.AppHash,
		Decision:   DecisionDeny,
		PolicyID:   decision.PolicyID,
		LaunchedAt: req.Now,
	}
	if decision.Allowed {
		entry.Decision = DecisionAllow
	}
	if err := s.auditor.Log(entry); err != nil {
		log.Printf("epm: audit log failed: %v", err)
	}
}

// peerCredentials returns the UID and PID of the process on the other end of
// conn, via the SO_PEERCRED socket option. This is how the server
// authenticates a connection without trusting anything the client says about
// itself. Linux's SO_PEERCRED conveniently gives both in one call (unlike
// Windows' Named Pipe, which only exposes the client's PID directly, and
// unlike macOS's LOCAL_PEERCRED, which only exposes the UID) — see
// pipe_windows.go's GetNamedPipeClientProcessId and socket_darwin.go's
// peerCredUID for the platform equivalents.
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

// splitArgs splits a client-supplied extra-arguments string on whitespace.
// This is a simplification with no shell-quoting support (an argument
// containing a literal space cannot be expressed) — acceptable for the
// common case of flag-style arguments; a fuller implementation would use a
// proper shell-word-splitting algorithm if quoted arguments are needed.
func splitArgs(commandLine string) []string {
	return strings.Fields(commandLine)
}
