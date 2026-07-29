package transportbe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/service/rpcutil"
)

var (
	_ PolicyTransport = (*V2RPCTransport)(nil)
	_ EventTransport  = (*V2RPCTransport)(nil)
)

// V2RPCTransport targets the five dedicated EPM RPCs specified in
// docs/EPM-RPC-Contract-v2.md: agent_epm_get_policy, agent_epm_ack_policy,
// agent_epm_enqueue_events, agent_epm_submit_approval,
// agent_epm_poll_approvals. None of these exist on any backend today — this
// is the agent-side half of a contract with no live server to verify
// against yet (see the package doc comment).
type V2RPCTransport struct {
	cfg    *config.Config
	client *http.Client
}

// NewV2RPCTransport builds a V2RPCTransport.
func NewV2RPCTransport(cfg *config.Config) *V2RPCTransport {
	return &V2RPCTransport{cfg: cfg, client: httpx.NewClient(30 * time.Second)}
}

func (t *V2RPCTransport) Name() string { return "v2-rpc" }

// Probe calls agent_epm_get_policy with generation 0 — the cheapest real
// call this transport has, and the same one Fetch would make on a cold
// start, so a successful Probe is a genuine end-to-end check, not a
// synthetic ping.
func (t *V2RPCTransport) Probe(ctx context.Context) error {
	_, err := t.getPolicy(ctx, PolicyCursor{})
	return err
}

type getPolicyRequest struct {
	CursorGeneration int64 `json:"p_cursor_generation"`
}

type getPolicyResponse struct {
	Bundle *epm.SignedBundle `json:"bundle"`
}

func (t *V2RPCTransport) Fetch(ctx context.Context, cursor PolicyCursor) (*epm.SignedBundle, error) {
	return t.getPolicy(ctx, cursor)
}

func (t *V2RPCTransport) getPolicy(ctx context.Context, cursor PolicyCursor) (*epm.SignedBundle, error) {
	var out getPolicyResponse
	if err := t.call(ctx, "agent_epm_get_policy", getPolicyRequest{CursorGeneration: cursor.Generation}, &out); err != nil {
		return nil, err
	}
	return out.Bundle, nil
}

type ackPolicyRequest struct {
	BundleID string `json:"p_bundle_id"`
	Applied  bool   `json:"p_applied"`
	Note     string `json:"p_note,omitempty"`
}

func (t *V2RPCTransport) Ack(ctx context.Context, bundleID string, applied bool, note string) error {
	return t.call(ctx, "agent_epm_ack_policy", ackPolicyRequest{BundleID: bundleID, Applied: applied, Note: note}, nil)
}

type enqueueEventsRequest struct {
	AuditRows     []AuditRow        `json:"p_audit_rows,omitempty"`
	ProcessEvents []ProcessEventRow `json:"p_process_events,omitempty"`
}

// SendAudit and SendProcessEvents both target agent_epm_enqueue_events, each
// populating only their own field — see docs/EPM-RPC-Contract-v2.md. Both
// use rpcutil.WithEnqueueRetry, matching every other fire-and-forget enqueue
// call in this codebase (e.g. the audit-log Uploader).
func (t *V2RPCTransport) SendAudit(ctx context.Context, rows []AuditRow) error {
	if len(rows) == 0 {
		return nil
	}
	return t.enqueueEvents(ctx, enqueueEventsRequest{AuditRows: rows})
}

func (t *V2RPCTransport) SendProcessEvents(ctx context.Context, events []ProcessEventRow) error {
	if len(events) == 0 {
		return nil
	}
	return t.enqueueEvents(ctx, enqueueEventsRequest{ProcessEvents: events})
}

func (t *V2RPCTransport) enqueueEvents(ctx context.Context, body enqueueEventsRequest) error {
	return rpcutil.WithEnqueueRetry(ctx, func(ctx context.Context) (int, error) {
		return t.callStatus(ctx, "agent_epm_enqueue_events", body, nil)
	})
}

type submitApprovalRequest struct {
	RequestID     string `json:"p_request_id"`
	RuleID        string `json:"p_rule_id"`
	UserID        string `json:"p_user_id"`
	AppPath       string `json:"p_app_path"`
	Justification string `json:"p_justification,omitempty"`
}

type submitApprovalResponse struct {
	ApprovalID string `json:"approval_id"`
}

func (t *V2RPCTransport) SubmitApproval(ctx context.Context, req ApprovalRequest) (string, error) {
	var out submitApprovalResponse
	// submitApprovalRequest's fields are identical to ApprovalRequest's in
	// name, type, and order — only the json tags differ (adding the RPC's
	// required p_-prefix) — so this is a plain type conversion, not a
	// reinterpretation of the data.
	if err := t.call(ctx, "agent_epm_submit_approval", submitApprovalRequest(req), &out); err != nil {
		return "", err
	}
	return out.ApprovalID, nil
}

type pollApprovalsRequest struct {
	ApprovalIDs []string `json:"p_approval_ids"`
}

type pollApprovalsResponse struct {
	Approvals []ApprovalStatus `json:"approvals"`
}

func (t *V2RPCTransport) PollApprovals(ctx context.Context, approvalIDs []string) ([]ApprovalStatus, error) {
	var out pollApprovalsResponse
	if err := t.call(ctx, "agent_epm_poll_approvals", pollApprovalsRequest{ApprovalIDs: approvalIDs}, &out); err != nil {
		return nil, err
	}
	return out.Approvals, nil
}

// call performs one RPC and decodes a 200 JSON response into out (skipped
// if out is nil). callStatus already wraps any non-200 response in a
// *StatusError, so call only needs to discard the status code callers that
// don't need it (i.e. everyone except enqueueEvents, via WithEnqueueRetry)
// would otherwise have to ignore explicitly.
func (t *V2RPCTransport) call(ctx context.Context, fn string, body, out any) error {
	_, err := t.callStatus(ctx, fn, body, out)
	return err
}

// callStatus is the shared low-level RPC call every method above builds on:
// POST JSON to /rest/v1/rpc/<fn> with the standard three headers
// (Content-Type, apikey, Authorization), decoding a 200 response into out
// when non-nil. It always returns the HTTP status code (0 for a
// network-level failure that never got a response), matching
// rpcutil.WithEnqueueRetry's (status int, err error) contract exactly so
// enqueueEvents can pass it through directly.
func (t *V2RPCTransport) callStatus(ctx context.Context, fn string, body, out any) (int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("v2-rpc: marshal %s request: %w", fn, err)
	}

	url := fmt.Sprintf("%s/rest/v1/rpc/%s", t.cfg.SupabaseURL, fn)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("v2-rpc: build %s request: %w", fn, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", t.cfg.SupabaseKey)
	req.Header.Set("Authorization", "Bearer "+t.cfg.GetAccessToken())

	resp, err := t.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("v2-rpc: %s: %w", fn, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, &StatusError{
			Status: resp.StatusCode,
			Err:    fmt.Errorf("v2-rpc: %s: status %d: %s", fn, resp.StatusCode, string(respBody)),
		}
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("v2-rpc: %s: decode response: %w", fn, err)
		}
	}
	return resp.StatusCode, nil
}
