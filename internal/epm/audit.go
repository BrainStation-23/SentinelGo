package epm

import (
	"fmt"
	"time"
)

// AuditEntry records a single elevation attempt (allowed or denied) for
// durable, offline-first audit logging.
//
// JSON tags are explicit and deliberately reproduce the Go field names
// byte-for-byte, matching the shape produced when this struct had no tags at
// all (json.Marshal falls back to the field name as the key). Nothing about
// the wire format has changed; the tags exist so that shape is pinned against
// a future field rename, rather than silently following one — any consumer
// downstream of internal/logging/epm_upload.go's epmAuditLogRecord (which
// marshals this struct straight into models.AuditLog.EventData) depends on
// these exact key names today. New fields (Phase 8's audit enrichment) must
// use new key names and add a "SchemaVersion" marker so EventData stays a
// strict superset of what a backend already parses.
type AuditEntry struct {
	RequestID   string         `json:"RequestID"`
	UserID      string         `json:"UserID"`
	AppPath     string         `json:"AppPath"`
	AppHash     string         `json:"AppHash"`
	Decision    PolicyDecision `json:"Decision"`
	PolicyID    string         `json:"PolicyID"`
	LaunchedAt  time.Time      `json:"LaunchedAt"`
	ScriptHash  string         `json:"ScriptHash"`  // "" unless the request was script/installer-scoped elevation
	ServiceName string         `json:"ServiceName"` // "" unless a service name was extracted from the request

	// SchemaVersion marks the presence of everything below as of Phase 8;
	// absent (zero value, which json:",omitempty" below drops from the
	// wire entirely) means a v1-shaped entry, letting a backend branch on
	// whether these fields are meaningful without inspecting each one.
	SchemaVersion int `json:"SchemaVersion,omitempty"`

	// Verdict/Mode are the full v2 verdict model (Phase 1) — a strict
	// superset of Decision's allow/deny axis; see Decision.LegacyDecision.
	Verdict Verdict       `json:"Verdict,omitempty"`
	Mode    ElevationMode `json:"Mode,omitempty"`
	// BundleID/RuleVersion/Specificity locate exactly which policy bundle
	// and rule produced this decision — see epm.Decision.
	BundleID    string `json:"BundleID,omitempty"`
	RuleVersion int    `json:"RuleVersion,omitempty"`
	Specificity int    `json:"Specificity,omitempty"`

	Publisher   string `json:"Publisher,omitempty"`
	CommandLine string `json:"CommandLine,omitempty"`

	// ProcessID is the launched process's PID (0 if nothing was launched,
	// e.g. a denied request). ParentPID/ParentPath describe the requesting
	// (unprivileged) process, not a Phase 6 procmon ancestry walk — that
	// correlation happens in internal/epm/enforce, not here.
	ProcessID  uint32 `json:"ProcessID,omitempty"`
	ParentPID  uint32 `json:"ParentPID,omitempty"`
	ParentPath string `json:"ParentPath,omitempty"`
	// ExitCode is a pointer so "unknown" (nil — the DB's -1 sentinel) is
	// distinguishable from a real exit code of 0 (success), which a plain
	// int zero value could not represent. Left nil by every caller today:
	// a launch is fire-and-forget from the Server's perspective (see
	// server.go's elevate), so the exit code is never actually known at
	// audit-write time. The column exists for a future asynchronous
	// updater, not populated by this phase.
	ExitCode *int `json:"ExitCode,omitempty"`

	// Justification/ApprovalID/GrantID are populated once Phase 5's
	// session helper and the interaction-verdict flow it depends on exist
	// — RequireJustification/RequireApproval verdicts currently always
	// fall back to FallbackVerdict (deny) with no interaction attempted
	// (see server.go's elevate), so these are always empty today.
	Justification string `json:"Justification,omitempty"`
	ApprovalID    string `json:"ApprovalID,omitempty"`
	GrantID       string `json:"GrantID,omitempty"`

	// DeviceContext is a JSON-encoded ContextSnapshot (Phase 4), captured
	// once Server holds a wired ContextProvider it can snapshot at audit
	// time — not yet threaded through server.go's audit() call site, so
	// always empty today.
	DeviceContext string `json:"DeviceContext,omitempty"`
	// MatchedConditions is a JSON array of the ConditionKind values that
	// actually fired in the winning rule (epm.Decision.Matched) — this is
	// what answers "why was I denied" from the audit trail alone, per
	// Decision.Indeterminate's own doc comment.
	MatchedConditions string `json:"MatchedConditions,omitempty"`

	AgentVersion string `json:"AgentVersion,omitempty"`
	// RetainUntil is reserved for a future per-row retention override;
	// epm-db-maintenance's default sweep (main_integration.go) compares
	// against LaunchedAt directly and does not require this to be set. A
	// pointer for the same reason as ExitCode: json's omitempty does not
	// treat a zero-value time.Time as empty (it is a non-nil struct), so a
	// plain time.Time field here would leak a "0001-01-01T00:00:00Z"
	// RetainUntil key onto the wire for every v1-shaped entry — exactly
	// the kind of accidental shape drift TestAuditEntry_JSONShapeUnchanged
	// exists to catch.
	RetainUntil *time.Time `json:"RetainUntil,omitempty"`
}

// AuditSink persists AuditEntry values. internal/store.EPMStore satisfies this
// interface, so internal/epm has no dependency on database/sql or SQLite —
// same duck-typing seam used for swsvc.Catalog in the software-sync handler.
type AuditSink interface {
	InsertAuditLog(entry AuditEntry) error
}

// Auditor writes elevation outcomes to an AuditSink.
type Auditor struct {
	sink AuditSink
}

// NewAuditor returns an Auditor that writes through sink.
func NewAuditor(sink AuditSink) *Auditor {
	return &Auditor{sink: sink}
}

// Log records entry via the underlying sink.
func (a *Auditor) Log(entry AuditEntry) error {
	if err := a.sink.InsertAuditLog(entry); err != nil {
		return fmt.Errorf("log elevation audit entry: %w", err)
	}
	return nil
}
