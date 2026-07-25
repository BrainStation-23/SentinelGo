// Package epm implements the platform-agnostic core of Endpoint Privilege
// Management: policy rules, the evaluation engine, file hashing, and audit
// logging. Platform-specific enforcement (session discovery, token handling,
// privileged process launch, local IPC) lives in _windows.go/_linux.go/_darwin.go
// files added in later phases; this file has no OS-specific code and no I/O.
package epm

import (
	"encoding/json"
	"fmt"
	"path"
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
type PolicyRule struct {
	ID        string         `json:"id"`
	AppPath   string         `json:"app_path"`  // exact path, or glob pattern (contains '*' or '?'); "" if not path-based
	AppHash   string         `json:"app_hash"`  // lowercase hex SHA-256; "" if not hash-based
	Publisher string         `json:"publisher"` // signer/publisher identity; "" if not publisher-based
	UserID    string         `json:"user_id"`   // user this rule applies to; "" matches any user
	Decision  PolicyDecision `json:"decision"`
	ExpiresAt time.Time      `json:"-"` // zero value = never expires; see (Un)MarshalJSON
	Priority  int            `json:"priority"`
}

// policyRuleWire is PolicyRule's JSON shape, with ExpiresAt as a plain string
// so an absent or empty value round-trips to the zero time.Time ("never
// expires") instead of failing time.Time's strict RFC3339 unmarshaling.
type policyRuleWire struct {
	ID        string         `json:"id"`
	AppPath   string         `json:"app_path"`
	AppHash   string         `json:"app_hash"`
	Publisher string         `json:"publisher"`
	UserID    string         `json:"user_id"`
	Decision  PolicyDecision `json:"decision"`
	ExpiresAt string         `json:"expires_at"`
	Priority  int            `json:"priority"`
}

// MarshalJSON encodes ExpiresAt as an RFC3339 string, or "" when it is the
// zero value (never expires).
func (r PolicyRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(policyRuleWire{
		ID:        r.ID,
		AppPath:   r.AppPath,
		AppHash:   r.AppHash,
		Publisher: r.Publisher,
		UserID:    r.UserID,
		Decision:  r.Decision,
		ExpiresAt: formatExpiresAtJSON(r.ExpiresAt),
		Priority:  r.Priority,
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
// tierNone if it does not match at all. Precedence (highest first): hash,
// publisher, exact path, glob path, wildcard.
func matchTier(rule *PolicyRule, req ElevationRequest) int {
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
		if isGlob(rule.AppPath) {
			// path.Match always treats '/' as the separator regardless of host
			// GOOS, so glob semantics are identical on every platform; normalize
			// backslashes (Windows-style paths) to '/' first so a pattern like
			// `C:\opt\*\tool.exe` still only matches one path segment per '*'
			// instead of filepath.Match's host-dependent behavior (on Windows,
			// filepath.Separator is '\', so '*' would otherwise cross '/'
			// boundaries left untouched by that separator check).
			ok, err := path.Match(normalizeSeparators(rule.AppPath), normalizeSeparators(req.AppPath))
			if err != nil || !ok {
				return tierNone
			}
			return tierPathGlob
		}
		if rule.AppPath == req.AppPath {
			return tierPathExact
		}
		return tierNone
	}
	// Rule targets no specific application field: wildcard (e.g. "allow this
	// user to elevate anything", scoped only by UserID).
	return tierWildcard
}

func isGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func normalizeSeparators(s string) string {
	return strings.ReplaceAll(s, `\`, "/")
}
