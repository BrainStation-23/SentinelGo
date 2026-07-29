package epm

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"sentinelgo/internal/epm/svcparse"
)

// Server is the ONE copy of the evaluate-hash-verify-launch-audit logic that
// pipe_windows.go, socket_linux.go, and socket_darwin.go each used to carry
// independently. A platform's Service wires a Transport (framing + peer
// identity) and a Launcher (the privileged launch primitive) into a Server
// and calls Serve — see service_windows.go/service_linux.go/service_darwin.go.
type Server struct {
	transport Transport
	launcher  Launcher
	ident     Identifier
	engine    *Engine
	rules     RuleProvider // used only if engine is nil — see NewServer
	auditor   *Auditor

	hashFile       func(string) (string, error)
	svcName        func(exe, args string) (string, bool)
	now            func() time.Time
	timeout        time.Duration
	processTracker ProcessTracker
	agentVersion   string
}

// ProcessTracker receives the root PID of every successful launch whose
// Constraints carry a ChildProcess policy (allowlist/deny), so Phase 6b's
// terminate-on-violation enforcement can later recognise a newly observed
// process as a descendant of that root. Structural, like RuleProvider/
// AuditSink/ContextProvider: the real implementation
// (internal/epm/enforce.Tracker) lives in its own package because it also
// depends on internal/epm/procmon for live process events, and this package
// must not import back down into either — importing procmon here would
// cycle (procmon already imports epm for Tri), which is exactly why
// devicectx and procmon are structured as one-way dependents of epm rather
// than the reverse. nil (the default) means no tracking happens at all,
// identical to epm_process_monitor_mode="off".
type ProcessTracker interface {
	TrackRoot(pid int, decision Decision)
}

// WithProcessTracker wires a ProcessTracker into the Server. See
// ProcessTracker's doc comment for why this is an interface rather than a
// concrete *enforce.Tracker field.
func WithProcessTracker(pt ProcessTracker) ServerOption {
	return func(s *Server) { s.processTracker = pt }
}

// WithAgentVersion sets the version string recorded on every Phase 8 audit
// entry (AuditEntry.AgentVersion). Empty (the default) leaves that field
// empty, exactly as every audit entry looked before Phase 8.
func WithAgentVersion(v string) ServerOption {
	return func(s *Server) { s.agentVersion = v }
}

// ServerOption configures optional Server behavior.
type ServerOption func(*Server)

// WithRequestTimeout overrides the default 30s per-connection deadline
// (matching today's Unix requestTimeout; Windows previously had none at all
// — see transport_windows.go's SetDeadline for how this now applies there
// too).
func WithRequestTimeout(d time.Duration) ServerOption {
	return func(s *Server) { s.timeout = d }
}

// WithServerClock overrides time.Now, for deterministic tests. Named
// distinctly from engine_v2.go's WithClock (an EngineOption) since Go
// functions cannot be overloaded by parameter/return type alone.
func WithServerClock(now func() time.Time) ServerOption {
	return func(s *Server) { s.now = now }
}

// WithHashFile overrides the file-hashing function. The Windows platform
// wiring (transport_windows.go) uses this to route through the same
// package-level computeFileHashFn seam pipe_integration_windows_test.go
// already stubs, so that existing test keeps controlling this Server's
// behavior even though the code path reaching it has moved.
func WithHashFile(fn func(string) (string, error)) ServerOption {
	return func(s *Server) { s.hashFile = fn }
}

// WithEngine pins the Server to a fixed *Engine instead of rebuilding one
// from RuleProvider.GetRules() on every request. Unused in Phase 2 (every
// platform still re-reads rules per request, matching v1); exists for Phase 3
// onward, where BundleManager owns one long-lived Engine it Swaps policy
// into.
func WithEngine(e *Engine) ServerOption {
	return func(s *Server) { s.engine = e }
}

const defaultRequestTimeout = 30 * time.Second

// NewServer builds a Server. rules supplies the live policy rule set, queried
// fresh (and re-upgraded through NewEngine) on every request — matching v1's
// behavior of never caching an Engine across requests, so a policy-sync that
// lands mid-run is picked up by the very next elevation request.
func NewServer(t Transport, l Launcher, ident Identifier, rules RuleProvider, auditor *Auditor, opts ...ServerOption) *Server {
	s := &Server{
		transport: t, launcher: l, ident: ident, rules: rules, auditor: auditor,
		hashFile: ComputeFileHash,
		svcName:  svcparse.ExtractServiceName,
		now:      time.Now,
		timeout:  defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Serve runs the accept loop until ctx is cancelled or Stop is called. Each
// connection is handled in its own goroutine, matching every platform's
// existing concurrency model.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.transport.Listen(ctx); err != nil {
		return err
	}
	for {
		// Checked at the top too, not just after a failed Accept: a
		// Transport's Close() can race ahead of ctx's own cancellation (a
		// caller may call Stop() before cancelling its context — see
		// pipe_integration_windows_test.go's cleanup order), so this is what
		// stops the loop promptly once ctx does land, rather than retrying
		// Accept once more first.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := s.transport.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("epm: accept: %v", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// Stop closes the transport, unblocking any pending Accept.
func (s *Server) Stop() error {
	return s.transport.Close()
}

// handleConn services exactly one request/response exchange and then closes
// the connection — v1 clients only ever send one message per connection, and
// nothing in Phase 2 requires holding a connection open past its answer (see
// protocol.go's Envelope doc comment on the conversational-not-persistent
// decision for prompts, which Phase 5 adds).
func (s *Server) handleConn(_ context.Context, c Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(s.now().Add(s.timeout))

	raw, err := c.ReadMessage()
	if err != nil {
		log.Printf("epm: read request: %v", err)
		return
	}

	version, op, body, requestID, err := DecodeRequest(raw)
	if err != nil {
		resp := Response{Error: err.Error()}
		if data, encErr := encodeResponse(resp); encErr == nil {
			_ = c.WriteMessage(data)
		}
		return
	}
	if requestID == "" {
		requestID = uuid.NewString()
	}

	var resp Response
	switch op {
	case OpElevate:
		var elevate ElevateBody
		if err := json.Unmarshal(body, &elevate); err != nil {
			resp = Response{RequestID: requestID, Error: fmt.Sprintf("malformed elevate body: %v", err)}
		} else {
			resp = s.elevate(c.Peer(), requestID, elevate)
		}
	default:
		// Any v2 op this Phase 2 server does not yet implement (hello,
		// prompt_result, approval_poll, query_policy, cancel, status) —
		// including a genuinely unknown op — gets a structured error rather
		// than silence, so a v2 client can distinguish "not supported yet"
		// from a dropped connection.
		resp = Response{RequestID: requestID, Error: fmt.Sprintf("unsupported operation %q", op)}
	}
	resp.RequestID = requestID
	if version == 2 {
		resp.ProtocolVersion = 2
	}

	data, err := encodeResponse(resp)
	if err != nil {
		log.Printf("epm: %v", err)
		return
	}
	if err := c.WriteMessage(data); err != nil {
		log.Printf("epm: write response: %v", err)
	}
}

// elevate is the one remaining copy of what pipe_windows.go's
// evaluateAndLaunch and socket_linux.go/socket_darwin.go's evaluateAndLaunch
// each implemented independently: validate, hash, verify, evaluate policy,
// launch if allowed, audit unconditionally. peer's identity fields are
// authenticated by the Transport at Accept time; nothing here trusts
// anything the client sent for identity.
func (s *Server) elevate(peer PeerIdentity, requestID string, req ElevateBody) Response {
	resp := Response{RequestID: requestID}

	if err := validateAppPath(req.AppPath); err != nil {
		resp.Error = fmt.Sprintf("invalid app_path: %v", err)
		return resp
	}

	appHash, err := s.hashFile(req.AppPath)
	if err != nil {
		resp.Error = fmt.Sprintf("hash application: %v", err)
		return resp
	}
	// Publisher is best-effort: an unsigned or unverifiable binary just can't
	// match publisher-based rules, it isn't a hard failure of the request.
	var publisher string
	if s.ident != nil {
		publisher, _ = s.ident.Publisher(req.AppPath)
	}

	// The script's hash is always computed server-side from the file on disk
	// — a client-supplied hash would let a compromised client substitute a
	// different payload after the policy check.
	var scriptHash string
	if req.ScriptPath != "" {
		scriptHash, err = s.hashFile(req.ScriptPath)
		if err != nil {
			resp.Error = fmt.Sprintf("hash script: %v", err)
			return resp
		}
	}
	serviceName, _ := s.svcName(req.AppPath, req.CommandLine)

	rules, err := s.rules.GetRules()
	if err != nil {
		resp.Error = fmt.Sprintf("load policy rules: %v", err)
		return resp
	}

	elevReq := ElevationRequest{
		RequestID: requestID, UserID: peer.UserID,
		AppPath: req.AppPath, AppHash: appHash, Publisher: publisher,
		Now:                  s.now().UTC(),
		ScriptPath:           req.ScriptPath,
		ScriptHash:           scriptHash,
		ActualArgs:           req.Args,
		RequestedServiceName: serviceName,
	}

	engine := s.engine
	if engine == nil {
		engine = NewEngine(rules)
	}
	decision := engine.EvaluateV2(EvalInput{
		Now:     elevReq.Now,
		Request: upgradeRequest(elevReq),
	})

	resp.Reason = decision.Outcome.Reason
	resp.Verdict = decision.Outcome.Verdict
	resp.Mode = decision.Outcome.Mode
	resp.RuleID = decision.RuleID
	resp.BundleID = decision.BundleID
	if hasConstraints(decision.Outcome.Constraints) {
		c := decision.Outcome.Constraints
		resp.Constraints = &c
	}

	// Interaction verdicts (Prompt/RequireJustification/RequireApproval) have
	// no way to actually interact with the user yet — Phase 5 adds the
	// session helper this depends on. Until then, and for any client that
	// negotiated no such capability, they resolve to their FallbackVerdict
	// (default deny), never silently granting.
	effectiveVerdict := decision.Outcome.Verdict
	if effectiveVerdict.NeedsInteraction() {
		effectiveVerdict = decision.Outcome.EffectiveFallback()
		resp.Reason = fmt.Sprintf("%s requires interaction, which is not available on this connection; falling back to %s",
			decision.Outcome.Verdict, effectiveVerdict)
	}

	// shouldLaunch and resp.Allowed MUST use the same predicate: Allow and
	// AuditOnly are both allow-family (AuditOnly permits the launch — it only
	// differs from Allow in how the decision is later reported/reviewed, not
	// in whether the process runs), so a response claiming Allowed=true must
	// always correspond to an actual launch attempt, never a silent no-op.
	shouldLaunch := effectiveVerdict == VerdictAllow || effectiveVerdict == VerdictAuditOnly
	resp.Allowed = shouldLaunch
	legacyDecisionForAudit := PolicyDecision(DecisionDeny)
	if resp.Allowed {
		legacyDecisionForAudit = DecisionAllow
	}

	if shouldLaunch {
		spec := LaunchSpec{
			AppPath:     req.AppPath,
			CommandLine: req.CommandLine,
			ScriptPath:  req.ScriptPath,
			ScriptArgs:  req.Args,
			Constraints: decision.Outcome.Constraints,
		}

		launched, launchErr := s.launcher.Launch(peer, spec)
		if launchErr != nil {
			resp.Allowed = false
			resp.Error = fmt.Sprintf("launch failed: %v", launchErr)
			legacyDecisionForAudit = DecisionDeny
		} else {
			resp.ProcessID = launched.ProcessID
			if s.processTracker != nil {
				rootPID := launched.ProcessID
				if launched.TrackedPID != 0 {
					rootPID = launched.TrackedPID
				}
				s.processTracker.TrackRoot(int(rootPID), decision)
			}
		}
	}

	s.audit(elevReq, legacyDecisionForAudit, decision, req.CommandLine, resp.ProcessID)
	return resp
}

// audit writes one AuditEntry per elevation request — always, whether
// allowed, denied, or errored before a verdict was even reached (legacy
// still reflects that: decision defaults to deny). commandLine and
// processID come from elevate's own locals (req.CommandLine, resp.ProcessID)
// rather than decision/ElevationRequest, since neither of those carries them
// today and changing ElevationRequest's shape risks the v1/v2 differential
// test's byte-for-byte guarantee.
func (s *Server) audit(req ElevationRequest, legacy PolicyDecision, decision Decision, commandLine string, processID uint32) {
	if s.auditor == nil {
		return
	}
	entry := AuditEntry{
		RequestID: req.RequestID, UserID: req.UserID,
		AppPath: req.AppPath, AppHash: req.AppHash,
		Decision: legacy, PolicyID: decision.RuleID, LaunchedAt: req.Now,
		ScriptHash: req.ScriptHash, ServiceName: req.RequestedServiceName,

		SchemaVersion: 2,
		Verdict:       decision.Outcome.Verdict,
		Mode:          decision.Outcome.Mode,
		BundleID:      decision.BundleID,
		RuleVersion:   decision.RuleVersion,
		Specificity:   decision.Specificity,
		Publisher:     req.Publisher,
		CommandLine:   commandLine,
		ProcessID:     processID,
		AgentVersion:  s.agentVersion,
	}
	if len(decision.Matched) > 0 {
		if data, err := json.Marshal(decision.Matched); err == nil {
			entry.MatchedConditions = string(data)
		}
	}
	if err := s.auditor.Log(entry); err != nil {
		log.Printf("epm: audit log failed: %v", err)
	}
}

// validateAppPath rejects AppPath values that are not safe to launch with
// elevated privileges: empty, a UNC/device path (\\server\share, \\.\Device),
// or relative. Originally Windows-only (pipe_windows.go); applying it on
// every platform is a deliberate hardening bundled into the Phase 2 transport
// unification — Linux/Darwin never had an equivalent check before, even
// though a relative or otherwise ambiguous path is exactly as dangerous in an
// elevated context there as on Windows.
func validateAppPath(appPath string) error {
	if appPath == "" {
		return fmt.Errorf("app_path must not be empty")
	}
	cleaned := filepath.Clean(appPath)
	if strings.HasPrefix(cleaned, `\\`) {
		return fmt.Errorf("UNC and device paths are not permitted (got %q)", cleaned)
	}
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("app_path must be an absolute local path (got %q)", cleaned)
	}
	return nil
}
