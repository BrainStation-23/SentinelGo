package transportbe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinelgo/internal/logging"
	"sentinelgo/internal/taskstore"
)

// fakeUploader is a hand-rolled auditUploader: real *logging.EPMAuditUploader
// needs a live Supabase config to construct meaningfully, so tests drive
// this instead to control and assert exactly what SendAudit passes through.
type fakeUploader struct {
	gotRows []AuditRow
	err     error
}

func (f *fakeUploader) UploadEPMAuditRows(_ context.Context, src logging.EPMAuditSource) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	rows, err := src.GetUnsyncedAuditLogs(1000)
	if err != nil {
		return 0, err
	}
	f.gotRows = rows
	return len(rows), nil
}

func newTaskServer(t *testing.T, tasks []taskstore.Task, onUpdate func(taskID, status, note string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/v1/rpc/agent_get_tasks":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(taskstore.AgentTasksResponse{Tasks: tasks})
		case "/rest/v1/rpc/agent_update_task":
			var body struct {
				TaskID string `json:"p_task_id"`
				Status string `json:"p_status"`
				Note   string `json:"p_note"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if onUpdate != nil {
				onUpdate(body.TaskID, body.Status, body.Note)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestV1Piggyback_Fetch_SynthesizesBundleFromPendingTask(t *testing.T) {
	task := taskstore.Task{
		ID:   "task-abc",
		Slug: "epm-policy-sync",
		Payload: map[string]interface{}{
			"rules": []map[string]interface{}{
				{"id": "r1", "app_path": `C:\apps\tool.exe`, "decision": "allow"},
			},
		},
	}
	srv := newTaskServer(t, []taskstore.Task{task}, nil)
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	bundle, err := tr.Fetch(context.Background(), PolicyCursor{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if bundle == nil {
		t.Fatal("Fetch() returned nil bundle for a pending task")
	}
	if bundle.Algorithm != "" || bundle.Signature != "" {
		t.Errorf("synthesized v1 bundle must be unsigned, got Algorithm=%q Signature=%q", bundle.Algorithm, bundle.Signature)
	}

	var decoded struct {
		SchemaVersion int    `json:"schema_version"`
		BundleID      string `json:"bundle_id"`
		Mode          string `json:"mode"`
		Rules         []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(bundle.Payload, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", decoded.SchemaVersion)
	}
	if decoded.BundleID != v1BundlePrefix+"task-abc" {
		t.Errorf("BundleID = %q, want %q", decoded.BundleID, v1BundlePrefix+"task-abc")
	}
	if decoded.Mode != "full" {
		t.Errorf("Mode = %q, want full", decoded.Mode)
	}
	if len(decoded.Rules) != 1 || decoded.Rules[0].ID != "r1" {
		t.Errorf("Rules = %+v", decoded.Rules)
	}
}

func TestV1Piggyback_Fetch_NilWhenNoPendingTask(t *testing.T) {
	srv := newTaskServer(t, []taskstore.Task{{ID: "t1", Slug: "software-sync"}}, nil)
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	bundle, err := tr.Fetch(context.Background(), PolicyCursor{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if bundle != nil {
		t.Errorf("Fetch() = %+v, want nil", bundle)
	}
}

func TestV1Piggyback_Fetch_MissingRulesKeyIsError(t *testing.T) {
	task := taskstore.Task{ID: "task-bad", Slug: "epm-policy-sync", Payload: map[string]interface{}{}}
	srv := newTaskServer(t, []taskstore.Task{task}, nil)
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	_, err := tr.Fetch(context.Background(), PolicyCursor{})
	if err == nil {
		t.Fatal("Fetch() error = nil, want an error for a payload with no rules key")
	}
}

func TestV1Piggyback_Fetch_ExplicitEmptyRulesSynthesizesEmptyBundle(t *testing.T) {
	task := taskstore.Task{ID: "task-empty", Slug: "epm-policy-sync", Payload: map[string]interface{}{"rules": []interface{}{}}}
	srv := newTaskServer(t, []taskstore.Task{task}, nil)
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	bundle, err := tr.Fetch(context.Background(), PolicyCursor{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if bundle == nil {
		t.Fatal("Fetch() returned nil for an explicit empty rule set, want a bundle instructing 'clear policy'")
	}
}

func TestV1Piggyback_Ack_UpdatesOriginatingTask(t *testing.T) {
	var gotID, gotStatus, gotNote string
	srv := newTaskServer(t, nil, func(taskID, status, note string) {
		gotID, gotStatus, gotNote = taskID, status, note
	})
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	err := tr.Ack(context.Background(), v1BundlePrefix+"task-abc", true, "applied")
	if err != nil {
		t.Fatalf("Ack() error = %v", err)
	}
	if gotID != "task-abc" || gotStatus != "success" || gotNote != "applied" {
		t.Errorf("update task: id=%q status=%q note=%q", gotID, gotStatus, gotNote)
	}
}

func TestV1Piggyback_Ack_AppliedFalseReportsFailedStatus(t *testing.T) {
	var gotStatus string
	srv := newTaskServer(t, nil, func(_, status, _ string) { gotStatus = status })
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	_ = tr.Ack(context.Background(), v1BundlePrefix+"task-abc", false, "rejected")
	if gotStatus != "failed" {
		t.Errorf("status = %q, want failed", gotStatus)
	}
}

func TestV1Piggyback_Ack_RejectsForeignBundleID(t *testing.T) {
	tr := NewV1PiggybackTransport(testConfig("http://unused"), nil)
	err := tr.Ack(context.Background(), "some-v2-bundle-id", true, "")
	if err == nil {
		t.Fatal("Ack() error = nil, want an error for a bundleID this transport did not produce")
	}
}

func TestV1Piggyback_SendAudit_DelegatesToInjectedUploader(t *testing.T) {
	uploader := &fakeUploader{}
	tr := NewV1PiggybackTransport(testConfig("http://unused"), uploader)

	rows := []AuditRow{{ID: 1}, {ID: 2}}
	if err := tr.SendAudit(context.Background(), rows); err != nil {
		t.Fatalf("SendAudit() error = %v", err)
	}
	if len(uploader.gotRows) != 2 {
		t.Errorf("uploader received %d rows, want 2", len(uploader.gotRows))
	}
}

func TestV1Piggyback_SendAudit_EmptyIsNoop(t *testing.T) {
	uploader := &fakeUploader{}
	tr := NewV1PiggybackTransport(testConfig("http://unused"), uploader)
	if err := tr.SendAudit(context.Background(), nil); err != nil {
		t.Fatalf("SendAudit() error = %v", err)
	}
	if uploader.gotRows != nil {
		t.Error("uploader was called for an empty row set")
	}
}

func TestV1Piggyback_SendAudit_NoUploaderConfiguredIsError(t *testing.T) {
	tr := NewV1PiggybackTransport(testConfig("http://unused"), nil)
	err := tr.SendAudit(context.Background(), []AuditRow{{ID: 1}})
	if err == nil {
		t.Fatal("SendAudit() error = nil, want an error when no uploader is configured")
	}
}

func TestV1Piggyback_SendAudit_PropagatesUploaderError(t *testing.T) {
	uploader := &fakeUploader{err: errors.New("upload failed")}
	tr := NewV1PiggybackTransport(testConfig("http://unused"), uploader)
	err := tr.SendAudit(context.Background(), []AuditRow{{ID: 1}})
	if err == nil {
		t.Fatal("SendAudit() error = nil, want the uploader's error propagated")
	}
}

func TestV1Piggyback_UnsupportedEventMethods(t *testing.T) {
	tr := NewV1PiggybackTransport(testConfig("http://unused"), nil)

	if err := tr.SendProcessEvents(context.Background(), []ProcessEventRow{{}}); !errors.Is(err, ErrNotSupported) {
		t.Errorf("SendProcessEvents() error = %v, want ErrNotSupported", err)
	}
	if _, err := tr.SubmitApproval(context.Background(), ApprovalRequest{}); !errors.Is(err, ErrNotSupported) {
		t.Errorf("SubmitApproval() error = %v, want ErrNotSupported", err)
	}
	if _, err := tr.PollApprovals(context.Background(), []string{"a"}); !errors.Is(err, ErrNotSupported) {
		t.Errorf("PollApprovals() error = %v, want ErrNotSupported", err)
	}
}

func TestV1Piggyback_Probe_UsesGetTasks(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(taskstore.AgentTasksResponse{})
	}))
	defer srv.Close()

	tr := NewV1PiggybackTransport(testConfig(srv.URL), nil)
	if err := tr.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if !called {
		t.Error("Probe() did not call the backend")
	}
}

func TestV1Piggyback_Name(t *testing.T) {
	tr := NewV1PiggybackTransport(testConfig("http://unused"), nil)
	if tr.Name() != "v1-piggyback" {
		t.Errorf("Name() = %q", tr.Name())
	}
}
