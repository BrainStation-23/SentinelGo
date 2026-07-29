// Package epm implements the platform-agnostic core of Endpoint Privilege
// Management: policy rules, the evaluation engine, file hashing, and audit
// logging. Platform-specific enforcement (session discovery, token handling,
// privileged process launch, local IPC) lives in _windows.go/_linux.go/_darwin.go
// files added in later phases; this file has no OS-specific code and no I/O.
//
// # Installer Elevation Pattern
//
// Allowing an installer host (msiexec.exe, dpkg, rpm, a .pkg installer) by
// path or publisher grants the user the ability to install ANYTHING through
// it. The installer host itself is a trusted, unchanging system binary — what
// actually needs to be pinned is the installer payload the user wants to run.
// This is exactly PolicyRule.ScriptHash/AllowedArgs (see PolicyRule and
// matchTier) applied with AppPath set to the installer host rather than a
// script interpreter: no separate mechanism is needed.
//
// Windows MSI example — allow jsmith to run one specific tool.msi via
// msiexec.exe, silently, for the next two hours:
//
//	PolicyRule{
//		AppPath:     `C:\Windows\System32\msiexec.exe`,
//		ScriptHash:  "<sha256 of tool.msi>",
//		AllowedArgs: `/i "C:\Users\jsmith\Downloads\tool.msi" /qn`,
//		UserID:      `CONTOSO\jsmith`,
//		ExpiresAt:   <2 hours from now>,
//		Decision:    DecisionAllow,
//	}
//
// Linux .deb example — allow jsmith to install one specific tool.deb via
// dpkg, for the next two hours:
//
//	PolicyRule{
//		AppPath:     "/usr/bin/dpkg",
//		ScriptHash:  "<sha256 of tool.deb>",
//		AllowedArgs: "-i /tmp/tool.deb",
//		UserID:      "jsmith",
//		ExpiresAt:   <2 hours from now>,
//		Decision:    DecisionAllow,
//	}
//
// In both cases the agent computes ScriptHash server-side from the actual
// file on disk at request time (see ElevationRequest.ScriptHash), so a client
// cannot substitute a different payload after policy sync.
package epm

import (
	"encoding/json"
	"fmt"
	"time"
)

// PolicyDecision is the outcome a PolicyRule assigns to a matching request.
type PolicyDecision string

const (
	DecisionAllow PolicyDecision = "allow"
	DecisionDeny  PolicyDecision = "deny"
)

// PolicyRule describes a single EPM rule: which application it targets, which
// user it applies to, and what decision it carries. A rule can target an
// application by any combination of hash, publisher, and path; Engine.Evaluate
// picks the highest-priority matching field per request (see match tiers below).
//
// ScriptHash, AllowedArgs, and AllowedServiceName are additive constraints for
// script/installer elevation and service-scoped elevation (see matchTier and
// the "Installer Elevation Pattern" section below). A rule with ScriptHash set
// must also set AppPath (the interpreter); ScriptHash then takes precedence
// over AppHash/Publisher/AppPath on that rule — do not set both AppHash and
// ScriptHash on the same rule.
type PolicyRule struct {
	ID        string         `json:"id"`
	AppPath   string         `json:"app_path"`  // exact path, or glob pattern (contains '*' or '?'); "" if not path-based
	AppHash   string         `json:"app_hash"`  // lowercase hex SHA-256; "" if not hash-based
	Publisher string         `json:"publisher"` // signer/publisher identity; "" if not publisher-based
	UserID    string         `json:"user_id"`   // user this rule applies to; "" matches any user
	Decision  PolicyDecision `json:"decision"`
	ExpiresAt time.Time      `json:"-"` // zero value = never expires; see (Un)MarshalJSON
	Priority  int            `json:"priority"`

	// ScriptHash is the lowercase hex SHA-256 of a script/installer payload
	// launched via the interpreter named by AppPath (e.g. powershell.exe running
	// a .ps1, msiexec.exe running a .msi). "" if this rule is not script-scoped.
	ScriptHash string `json:"script_hash"`
	// AllowedArgs, when set, is the exact argument string (trimmed) the script
	// must be invoked with. "" means any arguments are allowed once ScriptHash
	// matches. Only meaningful when ScriptHash is set.
	AllowedArgs string `json:"allowed_args"`
	// AllowedServiceName scopes a rule to a single service/unit/app-pool name,
	// as extracted by internal/epm/svcparse. "" means no service constraint
	// (current behavior). See matchTier/serviceNameMatches.
	AllowedServiceName string `json:"allowed_service_name"`
}

// policyRuleWire is PolicyRule's JSON shape, with ExpiresAt as a plain string
// so an absent or empty value round-trips to the zero time.Time ("never
// expires") instead of failing time.Time's strict RFC3339 unmarshaling.
type policyRuleWire struct {
	ID                 string         `json:"id"`
	AppPath            string         `json:"app_path"`
	AppHash            string         `json:"app_hash"`
	Publisher          string         `json:"publisher"`
	UserID             string         `json:"user_id"`
	Decision           PolicyDecision `json:"decision"`
	ExpiresAt          string         `json:"expires_at"`
	Priority           int            `json:"priority"`
	ScriptHash         string         `json:"script_hash,omitempty"`
	AllowedArgs        string         `json:"allowed_args,omitempty"`
	AllowedServiceName string         `json:"allowed_service_name,omitempty"`
}

// MarshalJSON encodes ExpiresAt as an RFC3339 string, or "" when it is the
// zero value (never expires).
func (r PolicyRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(policyRuleWire{
		ID:                 r.ID,
		AppPath:            r.AppPath,
		AppHash:            r.AppHash,
		Publisher:          r.Publisher,
		UserID:             r.UserID,
		Decision:           r.Decision,
		ExpiresAt:          formatExpiresAtJSON(r.ExpiresAt),
		Priority:           r.Priority,
		ScriptHash:         r.ScriptHash,
		AllowedArgs:        r.AllowedArgs,
		AllowedServiceName: r.AllowedServiceName,
	})
}

// UnmarshalJSON accepts an absent or empty "expires_at" as "never expires"
// rather than failing time.Time's strict RFC3339 parsing.
func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	var wire policyRuleWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	r.ID = wire.ID
	r.AppPath = wire.AppPath
	r.AppHash = wire.AppHash
	r.Publisher = wire.Publisher
	r.UserID = wire.UserID
	r.Decision = wire.Decision
	r.Priority = wire.Priority
	r.ScriptHash = wire.ScriptHash
	r.AllowedArgs = wire.AllowedArgs
	r.AllowedServiceName = wire.AllowedServiceName

	if wire.ExpiresAt == "" {
		r.ExpiresAt = time.Time{}
		return nil
	}
	t, err := time.Parse(time.RFC3339, wire.ExpiresAt)
	if err != nil {
		return fmt.Errorf("policy rule %q: invalid expires_at: %w", wire.ID, err)
	}
	r.ExpiresAt = t
	return nil
}

func formatExpiresAtJSON(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// RuleProvider supplies the current policy rule set on demand. It exists so
// the enforcement layer (the IPC server) can always evaluate against the
// latest synced rules instead of a stale in-memory snapshot, without
// internal/epm taking a hard dependency on database/sql or SQLite.
// internal/store.EPMStore implements this interface structurally — the same
// duck-typing seam used for AuditSink.
type RuleProvider interface {
	GetRules() ([]PolicyRule, error)
}

// ElevationRequest describes a single request to run an application elevated.
type ElevationRequest struct {
	RequestID string
	UserID    string
	AppPath   string
	AppHash   string
	Publisher string
	Now       time.Time // evaluation time; injected so tests are deterministic

	// ScriptPath is the script/installer payload to run via the interpreter
	// named by AppPath; "" for direct binary elevation (existing behavior).
	ScriptPath string
	// ScriptHash is the SHA-256 of ScriptPath, computed by the privileged
	// agent server-side — never trust a client-supplied hash here.
	ScriptHash string
	// ActualArgs is the argument string the script is being invoked with.
	ActualArgs string
	// RequestedServiceName is the service/unit/app-pool name extracted from
	// AppPath+the command line by internal/epm/svcparse, when recognized.
	RequestedServiceName string
}

// ElevationResponse is the result of evaluating an ElevationRequest against a
// rule set.
type ElevationResponse struct {
	Allowed  bool
	PolicyID string
	Reason   string
}

// Engine, NewEngine, and Evaluate live in engine_v2.go. Evaluate's exact
// signature and behavior are preserved — see that file and adapter_v1.go —
// but the implementation is now the v2 condition-tree engine reached by
// upgrading each PolicyRule through UpgradeV1. The original linear-pass
// algorithm is preserved unmodified, under unexported names, in
// legacy_engine.go as the oracle for TestV1V2Differential.
