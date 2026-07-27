//go:build windows

package epm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"

	"sentinelgo/internal/epm/svcparse"
)

// PipeName is the Named Pipe path the user-space EPM client
// (cmd/sentinelgo-epm) connects to. Only one instance of the pipe is ever
// listening at a time; each connection is handled and closed before the next
// instance is created.
const PipeName = `\\.\pipe\sentinelgo-epm`

// pipeBufferSize is generous enough for the small JSON request/response
// messages this protocol exchanges; PIPE_TYPE_MESSAGE framing means each
// WriteFile call arrives as one discrete ReadFile on the other end, so there
// is no need for length-prefixing on top of it.
const pipeBufferSize = 64 * 1024

// pipeRequest is the wire shape a client sends: which application it wants
// elevated, and any extra arguments. The server never trusts a client-supplied
// user identity — it derives the requester's identity itself from the OS
// (GetNamedPipeClientProcessId → session → WTS token), so a compromised or
// lying client cannot claim to be a different user.
type pipeRequest struct {
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

// pipeResponse is the wire shape returned to the client.
type pipeResponse struct {
	RequestID string `json:"request_id"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProcessID uint32 `json:"process_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PipeServer is the Windows enforcement transport: it accepts elevation
// requests from the unprivileged user-space client over a Named Pipe,
// resolves the requester's real identity from the OS, evaluates policy, and —
// if allowed — launches the target process in the requester's own session.
type PipeServer struct {
	rules   RuleProvider
	auditor *Auditor

	mu      sync.Mutex
	current windows.Handle // the pipe instance currently blocked in ConnectNamedPipe, if any
}

// NewPipeServer builds a PipeServer. rules supplies the live policy rule set
// (queried fresh per request) and auditor records every decision.
func NewPipeServer(rules RuleProvider, auditor *Auditor) *PipeServer {
	return &PipeServer{rules: rules, auditor: auditor}
}

// Serve runs the accept loop until ctx is cancelled or Stop is called. Each
// connection is handled synchronously in its own goroutine; a fresh pipe
// instance is created for the next client as soon as the current one is
// connected, so multiple simultaneous requests are supported.
func (p *PipeServer) Serve(ctx context.Context) error {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;AU)")
	if err != nil {
		return fmt.Errorf("build pipe security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		handle, err := p.createInstance(sa)
		if err != nil {
			return fmt.Errorf("CreateNamedPipe: %w", err)
		}

		p.mu.Lock()
		p.current = handle
		p.mu.Unlock()

		err = windows.ConnectNamedPipe(handle, nil)
		// ERROR_PIPE_CONNECTED means a client raced in between create and
		// connect and is already attached — not a failure.
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			_ = windows.CloseHandle(handle)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("epm: ConnectNamedPipe: %v", err)
			continue
		}

		go p.handleConnection(handle)
	}
}

// Stop unblocks a pending ConnectNamedPipe call so Serve can observe context
// cancellation promptly instead of waiting indefinitely for the next client.
func (p *PipeServer) Stop() {
	p.mu.Lock()
	handle := p.current
	p.mu.Unlock()
	if handle != 0 {
		_ = windows.CancelIoEx(handle, nil)
	}
}

func (p *PipeServer) createInstance(sa *windows.SecurityAttributes) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return 0, err
	}
	return windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		pipeBufferSize,
		pipeBufferSize,
		0, // default timeout
		sa,
	)
}

// handleConnection services exactly one request/response exchange and then
// closes the pipe instance, matching how each CreateNamedPipe instance in
// Serve's loop is single-use.
func (p *PipeServer) handleConnection(handle windows.Handle) {
	defer func() {
		_ = windows.DisconnectNamedPipe(handle)
		_ = windows.CloseHandle(handle)
	}()

	var clientPID uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &clientPID); err != nil {
		log.Printf("epm: GetNamedPipeClientProcessId: %v", err)
		return
	}

	buf := make([]byte, pipeBufferSize)
	var n uint32
	if err := windows.ReadFile(handle, buf, &n, nil); err != nil {
		log.Printf("epm: ReadFile: %v", err)
		return
	}

	var req pipeRequest
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		p.reply(handle, pipeResponse{Error: fmt.Sprintf("malformed request: %v", err)})
		return
	}
	if req.RequestID == "" {
		req.RequestID = uuid.NewString()
	}

	resp := p.evaluateAndLaunch(req, clientPID)
	p.reply(handle, resp)
}

// Test seams: the identity-resolution and launch steps below all require
// real Windows session/token/Authenticode state that is not reliably
// available (or safe to depend on holding the right privileges for) in an
// automated test run. Replacing these package-level vars in a test lets
// pipe_integration_windows_test.go drive a real PipeServer end to end —
// real Named Pipe, real ACL, real JSON wire protocol, real EPMStore-backed
// policy evaluation and audit trail — without needing an actual interactive
// WTS session. Mirrors the var-seam pattern already used throughout
// internal/service/task/native (e.g. sync_software.go's getSoftwareListFn).
var (
	sessionIDForProcessFn = sessionIDForProcess
	queryUserTokenFn      = QueryUserToken
	userIDForTokenFn      = userIDForToken
	computeFileHashFn     = ComputeFileHash
	verifyAuthenticodeFn  = VerifyAuthenticode
)

// evaluateAndLaunch resolves the real requester identity from the OS,
// evaluates policy, and — if allowed — performs the elevated launch. It never
// trusts req's contents for identity, only for what to launch.
func (p *PipeServer) evaluateAndLaunch(req pipeRequest, clientPID uint32) pipeResponse {
	resp := pipeResponse{RequestID: req.RequestID}

	// Validate AppPath before doing any expensive work: it must be an absolute
	// local path (not a UNC \\server\share path or a relative path). A UNC path
	// would let a compromised client point the server at a binary on an
	// attacker-controlled network share; a relative path is ambiguous and
	// dangerous in a high-privilege context.
	if err := validateAppPath(req.AppPath); err != nil {
		resp.Error = fmt.Sprintf("invalid app_path: %v", err)
		return resp
	}

	sessionID, err := sessionIDForProcessFn(clientPID)
	if err != nil {
		resp.Error = fmt.Sprintf("resolve session: %v", err)
		return resp
	}

	userToken, err := queryUserTokenFn(sessionID)
	if err != nil {
		resp.Error = fmt.Sprintf("resolve user token: %v", err)
		return resp
	}
	defer func() { _ = userToken.Close() }()

	userID, err := userIDForTokenFn(userToken)
	if err != nil {
		resp.Error = fmt.Sprintf("resolve user identity: %v", err)
		return resp
	}

	appHash, hashErr := computeFileHashFn(req.AppPath)
	if hashErr != nil {
		resp.Error = fmt.Sprintf("hash application: %v", hashErr)
		return resp
	}
	// Publisher is best-effort: an unsigned file just can't match
	// publisher-based rules, it isn't a hard failure of the request.
	publisher, _ := verifyAuthenticodeFn(req.AppPath)

	// The script's hash is always computed server-side from the file on disk
	// — a client-supplied hash would let a compromised client substitute a
	// different payload after the policy check.
	var scriptHash string
	if req.ScriptPath != "" {
		var hashErr error
		scriptHash, hashErr = computeFileHashFn(req.ScriptPath)
		if hashErr != nil {
			resp.Error = fmt.Sprintf("hash script: %v", hashErr)
			return resp
		}
	}
	serviceName, _ := svcparse.ExtractServiceName(req.AppPath, req.CommandLine)

	rules, err := p.rules.GetRules()
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
		if pid, launchErr := p.launch(userToken, req); launchErr != nil {
			resp.Allowed = false
			resp.Error = fmt.Sprintf("launch failed: %v", launchErr)
		} else {
			resp.ProcessID = pid
		}
	}

	p.audit(elevReq, decision)
	return resp
}

// Test seams for the launch step; see the seam comment above evaluateAndLaunch.
var (
	duplicateAsPrimaryTokenFn = DuplicateAsPrimaryToken
	buildEnvironmentBlockFn   = BuildEnvironmentBlock
	launchAsUserFn            = LaunchAsUser
)

func (p *PipeServer) launch(userToken windows.Token, req pipeRequest) (uint32, error) {
	primary, err := duplicateAsPrimaryTokenFn(userToken)
	if err != nil {
		return 0, err
	}
	defer func() { _ = primary.Close() }()

	env, err := buildEnvironmentBlockFn(primary)
	if err != nil {
		return 0, err
	}
	defer func() { _ = env.Close() }()

	// req.AppPath is always the interpreter/executable to launch. When a
	// script is requested, the process's own command line must be
	// "interpreter <scriptPath> [args]", not just "interpreter [args]" — so
	// the quoted script path (plus its args) is passed as the extra
	// command-line content appended after the (separately quoted) appPath.
	commandLine := req.CommandLine
	if req.ScriptPath != "" {
		commandLine = quoteWindowsArg(req.ScriptPath)
		if req.Args != "" {
			commandLine += " " + req.Args
		}
	}

	result, err := launchAsUserFn(primary, req.AppPath, commandLine, env)
	if err != nil {
		return 0, err
	}
	return result.ProcessID, nil
}

func (p *PipeServer) audit(req ElevationRequest, decision ElevationResponse) {
	if p.auditor == nil {
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
	if err := p.auditor.Log(entry); err != nil {
		log.Printf("epm: audit log failed: %v", err)
	}
}

func (p *PipeServer) reply(handle windows.Handle, resp pipeResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("epm: marshal response: %v", err)
		return
	}
	var written uint32
	if err := windows.WriteFile(handle, data, &written, nil); err != nil {
		log.Printf("epm: WriteFile response: %v", err)
	}
}

// validateAppPath rejects AppPath values that are not safe to launch with
// elevated privileges:
//   - Empty paths are always invalid.
//   - UNC paths (\\server\share\...) must be rejected: they resolve across the
//     network and could point to a binary on an attacker-controlled share.
//   - Relative paths are ambiguous in an elevated context and must be absolute.
//
// The check uses filepath.IsAbs (which on Windows also returns false for
// device paths that don't begin with a drive letter or \\.\) and an explicit
// UNC prefix guard, so both \\server\share and \\?\UNC\server\share are
// caught.
func validateAppPath(appPath string) error {
	if appPath == "" {
		return fmt.Errorf("app_path must not be empty")
	}
	// Normalise separators before prefix checks.
	cleaned := filepath.Clean(appPath)
	// Reject UNC paths (\\server\share or \\.\Device or \\?\...).
	if strings.HasPrefix(cleaned, `\\`) {
		return fmt.Errorf("UNC and device paths are not permitted (got %q)", cleaned)
	}
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("app_path must be an absolute local path (got %q)", cleaned)
	}
	return nil
}
