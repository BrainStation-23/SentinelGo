package epm

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a JSON-friendly wrapper around time.Duration, accepting both a
// duration string ("2h") and a raw number of nanoseconds, and always
// marshaling as a string. Deliberately independent of config.Duration (the
// same small codec, reimplemented) rather than imported: internal/config
// already avoids a hard dependency on the EPM domain (see
// Config.GetEPMWindowsTokenType's doc comment), and internal/epm returns the
// favor by not depending on internal/config either — RuleV2/Outcome values
// are serialized straight into the epm_rules_v2.outcome JSON column, one
// layer below any config concern.
type Duration time.Duration

// UnmarshalJSON accepts a duration string ("5m") or a plain number of
// nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		if value == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", value, err)
		}
		*d = Duration(parsed)
		return nil
	default:
		return fmt.Errorf("invalid duration: %v", v)
	}
}

// MarshalJSON always encodes as a duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Verdict is the enforcement outcome a matched rule prescribes. It supersedes
// PolicyDecision as the full v2 vocabulary; PolicyDecision remains the v1
// wire/audit representation (see Verdict.LegacyDecision).
type Verdict string

const (
	VerdictAllow                Verdict = "allow"
	VerdictDeny                 Verdict = "deny"
	VerdictAuditOnly            Verdict = "audit_only"            // permit, but record as a would-deny
	VerdictMonitor              Verdict = "monitor"               // no elevation; observe and record
	VerdictPrompt               Verdict = "prompt"                // confirm with the user, then allow
	VerdictRequireJustification Verdict = "require_justification" // collect free text, then allow
	VerdictRequireApproval      Verdict = "require_approval"      // out-of-band reviewer decision
)

// Valid reports whether v is a recognised verdict.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictAllow, VerdictDeny, VerdictAuditOnly, VerdictMonitor,
		VerdictPrompt, VerdictRequireJustification, VerdictRequireApproval:
		return true
	}
	return false
}

// IsAllowFamily reports whether a rule carrying this verdict, when it can only
// be evaluated as Unknown, should be treated as NOT matching — i.e. every
// verdict whose normal effect is granting something. See the Unknown-handling
// rule in Engine.EvaluateV2: an allow-family rule never fires on unverifiable
// context, because that would grant something on a fact nobody could confirm.
func (v Verdict) IsAllowFamily() bool {
	switch v {
	case VerdictAllow, VerdictAuditOnly, VerdictPrompt,
		VerdictRequireJustification, VerdictRequireApproval:
		return true
	}
	return false
}

// IsDenyFamily is IsAllowFamily's complement for the two verdicts whose normal
// effect is withholding something. A deny-family rule DOES match on Unknown
// context, so denial stands rather than silently lapsing when a fact cannot
// be verified.
func (v Verdict) IsDenyFamily() bool {
	return v == VerdictDeny || v == VerdictMonitor
}

// NeedsInteraction reports whether this verdict requires talking to the user
// or an approver before an outcome is known.
func (v Verdict) NeedsInteraction() bool {
	return v == VerdictPrompt || v == VerdictRequireJustification || v == VerdictRequireApproval
}

// LegacyDecision projects v onto the v1 allow/deny axis, for the v1 wire
// response and the existing epm_audit_log.decision column. Interaction
// verdicts project to their eventual post-interaction outcome; callers that
// have not yet resolved the interaction should not call this until they have.
func (v Verdict) LegacyDecision() PolicyDecision {
	if v == VerdictAllow || v == VerdictAuditOnly {
		return DecisionAllow
	}
	return DecisionDeny
}

// ElevationMode describes the lifetime and manner of an allowed elevation.
// TokenType (Elevated/System/Filtered/UserOnly) is declared in tokentype.go;
// ElevationMode is orthogonal to it — a rule can combine any mode with any
// token type.
type ElevationMode string

const (
	ModeSilent    ElevationMode = "silent"     // default: elevate now, no UI, no grant record
	ModeRunOnce   ElevationMode = "run_once"   // one consumed grant (see epm_grants.uses_count, Phase 3)
	ModeTemporary ElevationMode = "temporary"  // grant valid for GrantWindow from first use
	ModeSession   ElevationMode = "session"    // valid until the requester's OS session ends
	ModeTimeBased ElevationMode = "time_based" // valid only inside an absolute window
	ModeEmergency ElevationMode = "emergency"  // break-glass: allow even offline/stale, force-audit
)

// Valid reports whether m is a recognised elevation mode, treating "" as
// valid (it means ModeSilent — the zero value must be the safe default).
func (m ElevationMode) Valid() bool {
	switch m {
	case "", ModeSilent, ModeRunOnce, ModeTemporary, ModeSession, ModeTimeBased, ModeEmergency:
		return true
	}
	return false
}

// EffectiveMode returns m, defaulting an empty value to ModeSilent.
func (m ElevationMode) EffectiveMode() ElevationMode {
	if m == "" {
		return ModeSilent
	}
	return m
}

// TokenUserOnly extends the TokenType vocabulary declared in tokentype.go
// (TokenElevated/TokenSystem/TokenFiltered — all Windows launch mechanics)
// with a fourth value meaningful for Monitor/AuditOnly verdicts: no elevation
// happens at all, so there is no token to derive. Declared here rather than in
// tokentype.go because it is a verdict-model concept, not a Windows launch
// mechanism; TokenType.Valid() (tokentype.go) covers all four regardless of
// which file declares which constant.
//
// TokenUserOnly indicates a verdict that performs no elevation at all
// (Monitor, AuditOnly): there is no privileged token to derive because
// nothing privileged is launched. See tokentype.go for the three token types
// that do launch something (TokenElevated, TokenSystem, TokenFiltered).
const TokenUserOnly TokenType = "user"

// ChildProcessPolicy constrains what an elevated process may spawn. The zero
// value, ChildInherit, is today's unconstrained behavior: children run
// unobserved, exactly as before this field existed.
type ChildProcessPolicy string

const (
	ChildInherit   ChildProcessPolicy = ""          // legacy: children inherit, unobserved
	ChildObserve   ChildProcessPolicy = "observe"   // record the tree, never act (Phase 6a)
	ChildAllowlist ChildProcessPolicy = "allowlist" // only ChildAllowed globs may run elevated
	ChildDeny      ChildProcessPolicy = "deny"      // any child is a violation
)

// Valid reports whether p is a recognised child-process policy.
func (p ChildProcessPolicy) Valid() bool {
	switch p {
	case ChildInherit, ChildObserve, ChildAllowlist, ChildDeny:
		return true
	}
	return false
}

// Constraints narrows how an allowed launch may behave. The zero value is
// today's unconstrained behavior on every field, so a v1-upgraded rule (see
// UpgradeV1) carries Constraints{} and nothing about its launch changes.
type Constraints struct {
	TokenType    TokenType          `json:"token_type,omitempty"`
	ChildProcess ChildProcessPolicy `json:"child_process,omitempty"`
	ChildAllowed []string           `json:"child_allowed,omitempty"` // path globs
	MaxRuntime   Duration           `json:"max_runtime,omitempty"`
	WorkingDir   string             `json:"working_dir,omitempty"`
	// RequireInteractiveSession denies the launch outright when the requester
	// has no interactive desktop session to render into (see Phase 6/procmon
	// and the Windows/Unix session-resolution code already in this package).
	RequireInteractiveSession bool `json:"require_interactive_session,omitempty"`
}

// EffectiveTokenType returns c.TokenType, defaulting an empty value to
// TokenElevated — the same default the Windows transport already applies (see
// PipeServer.elevationToken).
func (c Constraints) EffectiveTokenType() TokenType {
	if c.TokenType == "" {
		return TokenElevated
	}
	return c.TokenType
}

// hasConstraints reports whether c carries anything beyond the zero value.
// Constraints embeds a []string (ChildAllowed), so it is not comparable with
// == — this is the field-by-field check that stands in for one.
func hasConstraints(c Constraints) bool {
	return c.TokenType != "" || c.ChildProcess != "" || len(c.ChildAllowed) != 0 ||
		c.MaxRuntime != 0 || c.WorkingDir != "" || c.RequireInteractiveSession
}

// Outcome is the complete prescription a matched rule carries: not just
// allow/deny, but how the elevation should behave and what to do when the
// prescribed behavior cannot be carried out.
type Outcome struct {
	Verdict Verdict       `json:"verdict"`
	Mode    ElevationMode `json:"mode,omitempty"`
	// GrantWindow bounds ModeTemporary (validity from first use). Ignored by
	// every other mode.
	GrantWindow Duration    `json:"grant_window,omitempty"`
	Constraints Constraints `json:"constraints,omitempty"`
	// Message is shown to the user in a Prompt/RequireJustification dialog.
	Message string `json:"message,omitempty"`
	// JustificationMinLength is the minimum character count
	// RequireJustification demands before accepting the user's free-text
	// reason. Zero means any non-empty text is accepted.
	JustificationMinLength int `json:"justification_min_length,omitempty"`
	// ApprovalTTL bounds how long a RequireApproval request waits for a
	// reviewer before it is treated as denied.
	ApprovalTTL Duration `json:"approval_ttl,omitempty"`
	// FallbackVerdict applies when the prescribed interaction cannot actually
	// happen — prompts disabled, a v1 client, no interactive session, approval
	// backend unreachable. Empty means VerdictDeny: an interaction verdict
	// that cannot be carried out must not silently degrade to Allow.
	FallbackVerdict Verdict `json:"fallback_verdict,omitempty"`
	// Reason is a short, operator-facing explanation surfaced in the audit
	// trail and (for allow-adjacent verdicts) is not shown to the requester.
	Reason string `json:"reason,omitempty"`
}

// EffectiveFallback returns o.FallbackVerdict, defaulting an empty value to
// VerdictDeny — an interaction that cannot be carried out must fail closed,
// never silently grant.
func (o Outcome) EffectiveFallback() Verdict {
	if o.FallbackVerdict == "" {
		return VerdictDeny
	}
	return o.FallbackVerdict
}

// Decision is the engine's answer to an EvalInput: which rule matched (if
// any), at what specificity, and what it prescribes. It is a strict superset
// of ElevationResponse; the v1 struct is derived from it via Legacy so the two
// representations can never drift apart.
type Decision struct {
	Outcome     Outcome
	RuleID      string
	RuleVersion int
	GroupID     string
	BundleID    string
	Specificity int
	Priority    int
	// Matched lists the condition kinds that actually fired in the winning
	// rule's tree — the leaves that were true, not merely present.
	Matched []ConditionKind
	// Indeterminate lists condition kinds anywhere in the evaluated tree that
	// resolved Unknown, whether or not they affected the final verdict. Always
	// populated, even when a rule matched despite them (deny-family) or failed
	// to match because of them (allow-family) — this is what answers "why was
	// I denied" from the audit trail alone.
	Indeterminate []ConditionKind
	// Explain is populated only when EvalInput.Explain is set; see
	// compile.go's ExplainStep.
	Explain []ExplainStep
}

// Legacy projects d onto ElevationResponse, the v1 wire/API shape.
// PolicyID stays empty on a default-deny (no rule matched), matching v1's
// exact behavior (see legacyEvaluate).
func (d Decision) Legacy() ElevationResponse {
	if d.RuleID == "" {
		return ElevationResponse{
			Allowed: false,
			Reason:  d.Outcome.Reason,
		}
	}
	return ElevationResponse{
		Allowed:  d.Outcome.Verdict == VerdictAllow || d.Outcome.Verdict == VerdictAuditOnly,
		PolicyID: d.RuleID,
		Reason:   d.Outcome.Reason,
	}
}
