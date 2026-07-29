// Package transportbe abstracts EPM's backend transport behind two small
// interfaces — PolicyTransport (policy distribution) and EventTransport
// (audit/process-event upload, approval workflow) — so the agent can run
// against today's v1 piggyback (the existing agent_get_tasks/
// agent_update_task RPCs, reused rather than replaced) or a dedicated v2 RPC
// surface, and negotiate between them automatically.
//
// Phase 7 is agent-side plumbing only: this package, its two
// implementations, and the negotiation logic in negotiate.go are complete
// and tested, but nothing in the running agent calls into this package yet
// — main_integration.go's existing epm-policy-sync/epm-audit-sync scheduler
// tasks (see main_integration.go) are untouched by this work, and wiring
// this abstraction in place of them is a deliberately separate, later step
// once a real v2 backend exists to negotiate against. The actual Phase 7
// deliverable for the backend team is docs/EPM-RPC-Contract-v2.md, which
// this package's v2_rpc.go implements exactly.
package transportbe

import (
	"context"
	"errors"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/store"
)

// ErrNotSupported is returned by an EventTransport method the active
// transport has no backend equivalent for. v1-piggyback returns it from
// SendProcessEvents/SubmitApproval/PollApprovals: none of those have an
// existing v1 RPC to piggyback on (process telemetry and the approval
// workflow are new in this redesign), so pretending otherwise would
// silently invent backend behavior that does not exist today — exactly
// what "zero behavior change" for the v1 transport must not do. Only
// SendAudit has a genuine v1 equivalent (the existing EPM elevation-audit
// upload pipeline, see v1_piggyback.go).
var ErrNotSupported = errors.New("transportbe: not supported by this transport")

// StatusError carries an HTTP status code alongside the usual error text —
// V2RPCTransport wraps every non-200 RPC response in one, so negotiate.go
// can classify a probe failure (404/501 = "this endpoint does not exist,
// latch immediately"; 5xx = "transient, let the circuit breaker decide")
// without parsing status codes back out of an error string.
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

// PolicyCursor is the caller's position in the policy stream: the
// generation of the last bundle it successfully applied. 0 means "nothing
// applied yet, send everything."
type PolicyCursor struct {
	Generation int64
}

// PolicyTransport is how the agent obtains and acknowledges policy updates.
type PolicyTransport interface {
	// Name identifies the transport for logging ("v1-piggyback" | "v2-rpc").
	Name() string

	// Probe reports whether this transport is currently reachable and
	// functional, without side effects beyond the network round trip
	// itself — used by the negotiator (negotiate.go) to decide which
	// transport to use, never by ordinary sync operations.
	Probe(ctx context.Context) error

	// Fetch returns the next pending policy update as a signed bundle, or
	// (nil, nil) if there is nothing newer than cursor. Both transports
	// return the same shape: v2 fetches one pending bundle from the
	// dedicated RPC; v1 synthesizes an unsigned bundle from the legacy
	// epm-policy-sync task payload via epm.UpgradeV1 (Phase 1's proven v1
	// rule adapter — see v1_piggyback.go), so a caller applying the result
	// through epm.BundleManager.Apply behaves identically regardless of
	// which transport produced it.
	Fetch(ctx context.Context, cursor PolicyCursor) (*epm.SignedBundle, error)

	// Ack reports back whether bundleID was successfully applied. v2 calls
	// agent_epm_ack_policy; v1 calls agent_update_task against the
	// originating task ID captured when Fetch built the bundle.
	Ack(ctx context.Context, bundleID string, applied bool, note string) error
}

// AuditRow is a type alias (not a new struct) for store.EPMAuditRow: no
// import cycle risk (internal/store already depends one-way on internal/epm
// and this package's other dependencies — internal/logging, in
// particular — already import internal/store themselves), and an alias
// means a caller holding real rows from *store.EPMStore.GetUnsyncedAuditLogs
// never has to convert them.
type AuditRow = store.EPMAuditRow

// ProcessEventRow is the minimal shape EventTransport.SendProcessEvents
// uploads — Phase 6's procmon.ProcessEvent, pre-marshalled by the caller
// since this package must not import internal/epm/procmon (which would
// cycle: procmon already imports internal/epm for Tri, and this package
// already imports internal/epm too, but nothing stops procmon from being
// imported here directly... it is kept out anyway to preserve the same
// "leaf packages never depend on sibling leaf packages" shape devicectx/
// procmon/enforce already establish, so this package's own dependency
// graph stays easy to reason about independent of procmon's).
type ProcessEventRow struct {
	ObservedAtUnix int64
	EventData      []byte
}

// ApprovalRequest is what SubmitApproval sends when a rule's verdict is
// RequireApproval (Phase 1's verdict model) and Phase 5's session helper
// has collected a justification from the user.
type ApprovalRequest struct {
	RequestID     string
	RuleID        string
	UserID        string
	AppPath       string
	Justification string
}

// ApprovalStatus is one entry of what PollApprovals returns.
type ApprovalStatus struct {
	ApprovalID string
	Status     string // "pending" | "approved" | "denied" | "expired"
	Note       string
}

// EventTransport is how the agent uploads audit/process-event telemetry and
// runs the two-phase approval workflow (see the plan's Phase 2 discussion of
// why approval is two-phase: it can take minutes to hours, so the
// connection cannot be held open for it).
type EventTransport interface {
	Name() string
	Probe(ctx context.Context) error

	SendAudit(ctx context.Context, rows []AuditRow) error
	SendProcessEvents(ctx context.Context, events []ProcessEventRow) error
	SubmitApproval(ctx context.Context, req ApprovalRequest) (approvalID string, err error)
	PollApprovals(ctx context.Context, approvalIDs []string) ([]ApprovalStatus, error)
}
