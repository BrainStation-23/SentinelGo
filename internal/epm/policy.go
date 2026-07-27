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
	"path"
	"runtime"
	"strings"
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

// Match tiers, highest wins. A rule scores the tier of the most specific field
// it matched on; rules that don't match on any target field are wildcards.
const (
	tierHash      = 300
	tierPublisher = 200
	tierPathExact = 100
	tierPathGlob  = 50
	tierWildcard  = 10
	tierNone      = -1 // rule does not match the request at all
)

// Engine evaluates elevation requests against a fixed set of policy rules.
// Engine holds no external state and performs no I/O, so it is identical on
// every platform; only what happens after Evaluate returns is OS-specific.
type Engine struct {
	rules []PolicyRule
}

// NewEngine builds an Engine over rules. The caller is expected to have
// already loaded rules from durable storage (see internal/store.EPMStore).
func NewEngine(rules []PolicyRule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate selects the highest-priority rule matching req and returns its
// decision. When no rule matches, the request is denied by default.
func (e *Engine) Evaluate(req ElevationRequest) ElevationResponse {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	bestTier := tierNone
	bestPriority := 0
	var best *PolicyRule

	for i := range e.rules {
		rule := &e.rules[i]

		if !rule.ExpiresAt.IsZero() && rule.ExpiresAt.Before(now) {
			continue // expired: skip as if it did not exist
		}
		if rule.UserID != "" && rule.UserID != req.UserID {
			continue // scoped to a different user
		}

		tier := matchTier(rule, req)
		if tier == tierNone {
			continue
		}

		if best == nil || tier > bestTier || (tier == bestTier && rule.Priority > bestPriority) {
			bestTier = tier
			bestPriority = rule.Priority
			best = rule
		}
	}

	if best == nil {
		return ElevationResponse{
			Allowed: false,
			Reason:  "no matching policy (default deny)",
		}
	}

	return ElevationResponse{
		Allowed:  best.Decision == DecisionAllow,
		PolicyID: best.ID,
		Reason:   string(best.Decision),
	}
}

// matchTier returns the specificity tier at which rule matches req, or
// tierNone if it does not match at all. It computes the base tier (hash,
// publisher, exact path, glob path, wildcard, or the compound script-hash
// match) and then applies AllowedServiceName as a post-hoc filter that can
// veto — but never grant — a match, so it applies uniformly on top of any of
// the five base tiers.
func matchTier(rule *PolicyRule, req ElevationRequest) int {
	tier := baseTier(rule, req)
	if tier == tierNone {
		return tierNone
	}
	if !serviceNameMatches(rule, req) {
		return tierNone
	}
	return tier
}

// baseTier returns the specificity tier at which rule matches req, ignoring
// AllowedServiceName. Precedence (highest first): script-hash (compound with
// path), hash, publisher, exact path, glob path, wildcard.
func baseTier(rule *PolicyRule, req ElevationRequest) int {
	// ScriptHash is compound with AppPath: a rule targeting a script/installer
	// must match both the interpreter path and the script's own hash. This is
	// checked before AppHash/Publisher/AppPath so a rule author does not need
	// to reason about which of AppHash/ScriptHash "wins" — ScriptHash always
	// does when set. AppPath is required; a rule with ScriptHash but no
	// AppPath is a rule-authoring error and fails closed (never matches).
	if rule.ScriptHash != "" {
		if rule.AppPath == "" || !pathMatches(rule.AppPath, req.AppPath) {
			return tierNone
		}
		if rule.ScriptHash != req.ScriptHash {
			return tierNone
		}
		if rule.AllowedArgs != "" && strings.TrimSpace(req.ActualArgs) != rule.AllowedArgs {
			return tierNone
		}
		return tierHash
	}

	if rule.AppHash != "" {
		if rule.AppHash == req.AppHash {
			return tierHash
		}
		return tierNone
	}
	if rule.Publisher != "" {
		if rule.Publisher == req.Publisher {
			return tierPublisher
		}
		return tierNone
	}
	if rule.AppPath != "" {
		if !pathMatches(rule.AppPath, req.AppPath) {
			return tierNone
		}
		if isGlob(rule.AppPath) {
			return tierPathGlob
		}
		return tierPathExact
	}
	// Rule targets no specific application field: wildcard (e.g. "allow this
	// user to elevate anything", scoped only by UserID).
	return tierWildcard
}

// pathMatches reports whether actualPath matches pattern, either as an exact
// string or, when pattern contains glob metacharacters, via path.Match with
// separators normalized first.
//
// path.Match always treats '/' as the separator regardless of host GOOS, so
// glob semantics are identical on every platform; normalize backslashes
// (Windows-style paths) to '/' first so a pattern like `C:\opt\*\tool.exe`
// still only matches one path segment per '*' instead of filepath.Match's
// host-dependent behavior (on Windows, filepath.Separator is '\', so '*'
// would otherwise cross '/' boundaries left untouched by that separator
// check).
func pathMatches(pattern, actualPath string) bool {
	if isGlob(pattern) {
		ok, err := path.Match(normalizeSeparators(pattern), normalizeSeparators(actualPath))
		return err == nil && ok
	}
	return pattern == actualPath
}

// serviceNameMatches reports whether rule's AllowedServiceName constraint (if
// any) is satisfied by req. A rule with no AllowedServiceName is unconstrained
// (always true). A rule with AllowedServiceName set requires req to have
// extracted a service name, and for it to equal AllowedServiceName; if the
// agent could not extract a service name from the request, the rule does not
// match (safer to deny than to allow an unknown target).
func serviceNameMatches(rule *PolicyRule, req ElevationRequest) bool {
	if rule.AllowedServiceName == "" {
		return true
	}
	if req.RequestedServiceName == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(rule.AllowedServiceName, req.RequestedServiceName)
	}
	return rule.AllowedServiceName == req.RequestedServiceName
}

func isGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func normalizeSeparators(s string) string {
	return strings.ReplaceAll(s, `\`, "/")
}
