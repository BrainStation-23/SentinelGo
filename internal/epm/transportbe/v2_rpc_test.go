package transportbe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
)

func testConfig(url string) *config.Config {
	return &config.Config{SupabaseURL: url, SupabaseKey: "test-key", AccessToken: "test-token"}
}

func TestV2RPC_Fetch_DecodesBundle(t *testing.T) {
	bundle := &epm.SignedBundle{Payload: json.RawMessage(`{"bundle_id":"b1"}`), Algorithm: "ed25519"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_epm_get_policy" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if key := r.Header.Get("apikey"); key != "test-key" {
			t.Errorf("apikey = %q", key)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("Authorization = %q", auth)
		}
		var req getPolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CursorGeneration != 42 {
			t.Errorf("CursorGeneration = %d, want 42", req.CursorGeneration)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(getPolicyResponse{Bundle: bundle})
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	got, err := tr.Fetch(context.Background(), PolicyCursor{Generation: 42})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got == nil || string(got.Payload) != string(bundle.Payload) {
		t.Errorf("Fetch() = %+v, want %+v", got, bundle)
	}
}

func TestV2RPC_Fetch_NilBundleWhenNothingPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(getPolicyResponse{Bundle: nil})
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	got, err := tr.Fetch(context.Background(), PolicyCursor{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if got != nil {
		t.Errorf("Fetch() = %+v, want nil", got)
	}
}

func TestV2RPC_Fetch_404IsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	_, err := tr.Fetch(context.Background(), PolicyCursor{})
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Fetch() error = %v, want a *StatusError", err)
	}
	if statusErr.Status != 404 {
		t.Errorf("Status = %d, want 404", statusErr.Status)
	}
}

func TestV2RPC_Ack_SendsExpectedBody(t *testing.T) {
	var got ackPolicyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_epm_ack_policy" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	if err := tr.Ack(context.Background(), "bundle-1", true, "applied ok"); err != nil {
		t.Fatalf("Ack() error = %v", err)
	}
	if got.BundleID != "bundle-1" || !got.Applied || got.Note != "applied ok" {
		t.Errorf("Ack request = %+v", got)
	}
}

func TestV2RPC_SendAudit_PopulatesAuditRowsField(t *testing.T) {
	var got enqueueEventsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_epm_enqueue_events" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	rows := []AuditRow{{ID: 1}, {ID: 2}}
	if err := tr.SendAudit(context.Background(), rows); err != nil {
		t.Fatalf("SendAudit() error = %v", err)
	}
	if len(got.AuditRows) != 2 || len(got.ProcessEvents) != 0 {
		t.Errorf("request = %+v, want 2 audit rows and 0 process events", got)
	}
}

func TestV2RPC_SendAudit_EmptyIsNoop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	if err := tr.SendAudit(context.Background(), nil); err != nil {
		t.Fatalf("SendAudit() error = %v", err)
	}
	if called {
		t.Error("SendAudit(nil) made an HTTP call, want none")
	}
}

func TestV2RPC_SendProcessEvents_PopulatesProcessEventsField(t *testing.T) {
	var got enqueueEventsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	events := []ProcessEventRow{{ObservedAtUnix: 100}}
	if err := tr.SendProcessEvents(context.Background(), events); err != nil {
		t.Fatalf("SendProcessEvents() error = %v", err)
	}
	if len(got.ProcessEvents) != 1 || len(got.AuditRows) != 0 {
		t.Errorf("request = %+v, want 1 process event and 0 audit rows", got)
	}
}

func TestV2RPC_SubmitApproval_ReturnsApprovalID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_epm_submit_approval" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var req submitApprovalRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RuleID != "rule-1" {
			t.Errorf("RuleID = %q, want rule-1", req.RuleID)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(submitApprovalResponse{ApprovalID: "appr-1"})
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	id, err := tr.SubmitApproval(context.Background(), ApprovalRequest{RuleID: "rule-1"})
	if err != nil {
		t.Fatalf("SubmitApproval() error = %v", err)
	}
	if id != "appr-1" {
		t.Errorf("approvalID = %q, want appr-1", id)
	}
}

func TestV2RPC_PollApprovals_ReturnsStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_epm_poll_approvals" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var req pollApprovalsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.ApprovalIDs) != 1 || req.ApprovalIDs[0] != "appr-1" {
			t.Errorf("ApprovalIDs = %v", req.ApprovalIDs)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(pollApprovalsResponse{
			Approvals: []ApprovalStatus{{ApprovalID: "appr-1", Status: "approved"}},
		})
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	statuses, err := tr.PollApprovals(context.Background(), []string{"appr-1"})
	if err != nil {
		t.Fatalf("PollApprovals() error = %v", err)
	}
	if len(statuses) != 1 || statuses[0].Status != "approved" {
		t.Errorf("statuses = %+v", statuses)
	}
}

func TestV2RPC_Probe_UsesGetPolicy(t *testing.T) {
	calledPath := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(getPolicyResponse{})
	}))
	defer srv.Close()

	tr := NewV2RPCTransport(testConfig(srv.URL))
	if err := tr.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if calledPath != "/rest/v1/rpc/agent_epm_get_policy" {
		t.Errorf("Probe() called %q, want agent_epm_get_policy", calledPath)
	}
}
