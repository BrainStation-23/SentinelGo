package transportbe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/taskstore"
)

// Compile-time proof that the real production uploaders satisfy
// auditUploader — see auditUploader's doc comment for why this is not
// automatic just because the method sets look alike.
var (
	_ auditUploader   = (*logging.EPMAuditUploader)(nil)
	_ auditUploader   = (*logging.LoggingIntegration)(nil)
	_ PolicyTransport = (*V1PiggybackTransport)(nil)
	_ EventTransport  = (*V1PiggybackTransport)(nil)
)

// v1BundlePrefix marks a SignedBundle as one V1PiggybackTransport
// synthesized from a legacy task, and carries the originating task ID so
// Ack can find it again — see Fetch/Ack.
const v1BundlePrefix = "v1-task-"

// auditUploader is the shape logging.EPMAuditUploader and
// logging.LoggingIntegration already implement — referencing
// logging.EPMAuditSource by name (rather than a locally re-declared
// look-alike interface) is required, not just tidier: Go interface
// satisfaction needs the parameter type of UploadEPMAuditRows to match
// exactly, so a structurally-identical-but-differently-named interface
// here would silently fail to be implemented by the real type. Injected
// rather than this package constructing its own *logging.EPMAuditUploader,
// so V1PiggybackTransport.SendAudit is a genuine wrapper around the
// existing, already-tested production upload pipeline (batching, retry,
// auth recovery, category tagging) — reimplementing any of that here would
// risk silently diverging from it, exactly the opposite of "zero behavior
// change".
type auditUploader interface {
	UploadEPMAuditRows(ctx context.Context, src logging.EPMAuditSource) (int, error)
}

// V1PiggybackTransport implements both PolicyTransport and EventTransport
// on top of exactly what exists today: the agent_get_tasks/
// agent_update_task RPCs (via taskstore.Client) for policy, and the
// existing EPM elevation-audit upload pipeline (via the injected
// auditUploader) for events. See transport.go's ErrNotSupported for what
// this transport deliberately does not implement.
type V1PiggybackTransport struct {
	cfg      *config.Config
	client   *taskstore.Client
	uploader auditUploader
}

// NewV1PiggybackTransport builds a V1PiggybackTransport. uploader may be
// nil if the caller never intends to call SendAudit (Probe/Fetch/Ack do not
// need it).
func NewV1PiggybackTransport(cfg *config.Config, uploader auditUploader) *V1PiggybackTransport {
	return &V1PiggybackTransport{
		cfg:      cfg,
		client:   taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken()),
		uploader: uploader,
	}
}

func (t *V1PiggybackTransport) Name() string { return "v1-piggyback" }

// Probe fetches tasks — the same call Fetch itself makes — since v1 has no
// dedicated health-check endpoint and agent_get_tasks is already the
// lightest read available.
func (t *V1PiggybackTransport) Probe(ctx context.Context) error {
	t.client.UpdateToken(t.cfg.GetAccessToken())
	_, err := t.client.GetTasks(ctx)
	return err
}

// Fetch finds the first pending epm-policy-sync task (agent_get_tasks
// already returns only actionable tasks server-side — see
// main_integration.go's epmPolicySyncHandler, which applies the same
// no-client-side-status-filter assumption) and synthesizes an unsigned
// SignedBundle from it via epm.UpgradeV1, Phase 1's proven v1-rule adapter.
// cursor is ignored: v1 has no generation concept, every pending task is a
// full replacement, exactly as today's native epm-policy-sync handler
// treats it.
func (t *V1PiggybackTransport) Fetch(ctx context.Context, _ PolicyCursor) (*epm.SignedBundle, error) {
	t.client.UpdateToken(t.cfg.GetAccessToken())
	resp, err := t.client.GetTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("v1-piggyback: fetch tasks: %w", err)
	}

	for _, task := range resp.Tasks {
		if task.Slug != "epm-policy-sync" {
			continue
		}
		return v1TaskToBundle(task)
	}
	return nil, nil
}

// Ack reports a synthesized bundle's apply result back via
// agent_update_task, recovering the originating task ID from bundleID (see
// v1BundlePrefix).
func (t *V1PiggybackTransport) Ack(ctx context.Context, bundleID string, applied bool, note string) error {
	taskID, ok := strings.CutPrefix(bundleID, v1BundlePrefix)
	if !ok {
		return fmt.Errorf("v1-piggyback: Ack: bundle %q was not produced by this transport", bundleID)
	}
	status := "success"
	if !applied {
		status = "failed"
	}
	t.client.UpdateToken(t.cfg.GetAccessToken())
	return t.client.UpdateTask(ctx, taskID, status, note)
}

// SendAudit uploads rows through the existing EPM elevation-audit pipeline
// (see auditUploader) by presenting them as an in-memory EPMAuditSource —
// no new HTTP call, batching, or retry logic here at all.
func (t *V1PiggybackTransport) SendAudit(ctx context.Context, rows []AuditRow) error {
	if len(rows) == 0 {
		return nil
	}
	if t.uploader == nil {
		return fmt.Errorf("v1-piggyback: SendAudit: no uploader configured")
	}
	_, err := t.uploader.UploadEPMAuditRows(ctx, &memAuditSource{rows: rows})
	return err
}

// SendProcessEvents, SubmitApproval, and PollApprovals have no v1
// equivalent — see ErrNotSupported.
func (t *V1PiggybackTransport) SendProcessEvents(context.Context, []ProcessEventRow) error {
	return ErrNotSupported
}

func (t *V1PiggybackTransport) SubmitApproval(context.Context, ApprovalRequest) (string, error) {
	return "", ErrNotSupported
}

func (t *V1PiggybackTransport) PollApprovals(context.Context, []string) ([]ApprovalStatus, error) {
	return nil, ErrNotSupported
}

// memAuditSource adapts a fixed, caller-supplied []AuditRow into the
// EPMAuditSource shape the existing upload pipeline expects, so
// SendAudit's push-based signature can drive that pull-based pipeline
// without it ever touching a real database.
type memAuditSource struct {
	rows []AuditRow
}

func (s *memAuditSource) GetUnsyncedAuditLogs(limit int) ([]AuditRow, error) {
	if limit > 0 && limit < len(s.rows) {
		return s.rows[:limit], nil
	}
	return s.rows, nil
}

// MarkAuditLogSynced is a no-op: this in-memory source has no persistence
// of its own for the uploader to update — the caller's real store (if any)
// is responsible for marking rows synced once SendAudit returns nil.
func (s *memAuditSource) MarkAuditLogSynced([]int64) error { return nil }

// parseV1Rules mirrors internal/service/task/native/epm_policy_sync.go's
// unexported parseEPMRules exactly, including the absent-vs-empty
// distinction documented there (absent "rules" key is a hard failure, an
// explicit "rules": [] is a legitimate "clear policy" instruction) — kept
// as a small local copy rather than exporting and importing the original,
// to avoid touching that already-shipped, already-tested file for a
// dependency only this package needs.
func parseV1Rules(payload map[string]interface{}) ([]epm.PolicyRule, error) {
	raw, ok := payload["rules"]
	if !ok || raw == nil {
		return nil, fmt.Errorf(`payload has no "rules" key`)
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal rules payload: %w", err)
	}

	var rules []epm.PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("unmarshal rules payload: %w", err)
	}
	return rules, nil
}

func v1TaskToBundle(task taskstore.Task) (*epm.SignedBundle, error) {
	rules, err := parseV1Rules(task.Payload)
	if err != nil {
		return nil, fmt.Errorf("v1-piggyback: task %s: %w", task.ID, err)
	}

	upgraded := make([]epm.RuleV2, len(rules))
	for i, r := range rules {
		upgraded[i] = epm.UpgradeV1(r)
	}

	bundle := epm.PolicyBundle{
		SchemaVersion: 1,
		BundleID:      v1BundlePrefix + task.ID,
		Mode:          "full",
		IssuedAt:      time.Now().UTC(),
		Rules:         upgraded,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("v1-piggyback: marshal synthesized bundle: %w", err)
	}
	// Unsigned: Algorithm/KeyID/Signature all left empty. VerifyBundle
	// under SignatureModeOff or SignatureModeWarn accepts this — v1 has
	// never had a signing story, and requiring one here would be a new
	// behavior, not a re-expression of an existing one.
	return &epm.SignedBundle{Payload: payload}, nil
}
