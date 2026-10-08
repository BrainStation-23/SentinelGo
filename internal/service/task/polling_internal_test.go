package task

// White-box tests for TaskPollingService paths that the black-box tests in
// polling_test.go cannot reach: store failures, the connectivity gate, the
// retry reporting loop, and every handleRestartContext branch.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// taskUpdate is one UpdateTask call recorded by fakeTaskClient.
type taskUpdate struct {
	id, status, note string
}

// fakeTaskClient records UpdateTask calls and fails them on demand.
type fakeTaskClient struct {
	mu        sync.Mutex
	tasks     []taskstore.Task
	getErr    error
	getCalls  int
	updates   []taskUpdate
	failIDs   map[string]bool // UpdateTask fails for these task IDs
	failState map[string]bool // UpdateTask fails for these statuses
}

func (c *fakeTaskClient) GetTasks(_ context.Context) (*taskstore.AgentTasksResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCalls++
	if c.getErr != nil {
		return nil, c.getErr
	}
	return &taskstore.AgentTasksResponse{Tasks: c.tasks}, nil
}

func (c *fakeTaskClient) UpdateTask(_ context.Context, id, status, note string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updates = append(c.updates, taskUpdate{id, status, note})
	if c.failIDs[id] || c.failState[status] {
		return fmt.Errorf("update %s rejected", id)
	}
	return nil
}

func (c *fakeTaskClient) recorded() []taskUpdate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]taskUpdate(nil), c.updates...)
}

type failingConnectivity struct{ err error }

func (f failingConnectivity) CheckInternet(_ context.Context) error { return f.err }

// newPollingFixture builds a polling service on a fresh database in a temp dir
// whose config path makes restartctx.PathFor resolve inside that dir.
func newPollingFixture(t *testing.T, client TaskClient) (*TaskPollingService, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tasks.db")
	cfg := &config.Config{Path: filepath.Join(dir, "config.json")}
	svc, err := NewTaskPollingServiceWithClient(cfg, dbPath, client)
	if err != nil {
		t.Fatalf("NewTaskPollingServiceWithClient: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc, dbPath
}

func seedTasks(t *testing.T, svc *TaskPollingService, tasks ...taskstore.Task) {
	t.Helper()
	if err := svc.store.StoreTasks(tasks); err != nil {
		t.Fatalf("StoreTasks: %v", err)
	}
}

// taskRow reads a task's status, note and sync flag through a second
// connection, since TaskStore has no single-task getter.
type taskRow struct {
	status, note string
	synced       bool
}

func readTaskRow(t *testing.T, dbPath, id string) taskRow {
	t.Helper()
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	var r taskRow
	var note sql.NullString
	var synced int
	if err := db.QueryRow(`SELECT status, note, is_synced FROM tasks WHERE id = ?`, id).
		Scan(&r.status, &note, &synced); err != nil {
		t.Fatalf("read task %s: %v", id, err)
	}
	r.note, r.synced = note.String, synced == 1
	return r
}

func execSQL(t *testing.T, dbPath, query string, args ...any) {
	t.Helper()
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// ── handleRestartContext ─────────────────────────────────────────────────────

func TestHandleRestartContext_NoConfigPath_NoOp(t *testing.T) {
	(&TaskPollingService{}).handleRestartContext()                      // nil cfg
	(&TaskPollingService{cfg: &config.Config{}}).handleRestartContext() // empty Path
}

func TestHandleRestartContext_MessagePerReason(t *testing.T) {
	tests := []struct {
		reason, fromVersion, wantNote string
	}{
		{"agent-update", "v1.0.0", fmt.Sprintf("Agent updated from v1.0.0 to %s and restarted successfully.", config.Version)},
		{"device-reboot", "", "Device rebooted successfully. Agent is back online."},
		{"manual", "", "Agent restarted (reason: manual)."},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			svc, dbPath := newPollingFixture(t, &fakeTaskClient{})
			seedTasks(t, svc, taskstore.Task{ID: "rc-1", Status: "executing"})
			if err := restartctx.Write(restartctx.PathFor(svc.cfg.Path), restartctx.Context{
				TaskID: "rc-1", Reason: tt.reason, FromVersion: tt.fromVersion,
			}); err != nil {
				t.Fatalf("restartctx.Write: %v", err)
			}

			svc.handleRestartContext()

			got := readTaskRow(t, dbPath, "rc-1")
			if got.status != "success" || got.note != tt.wantNote {
				t.Errorf("task = {%q, %q}, want {success, %q}", got.status, got.note, tt.wantNote)
			}
			if got.synced {
				t.Error("restart-context result must stay unsynced so SyncPendingTasks reports it")
			}
		})
	}
}

func TestHandleRestartContext_MalformedFile_LeavesTaskUntouched(t *testing.T) {
	svc, dbPath := newPollingFixture(t, &fakeTaskClient{})
	seedTasks(t, svc, taskstore.Task{ID: "rc-bad", Status: "executing"})
	ctxPath := restartctx.PathFor(svc.cfg.Path)
	if err := os.WriteFile(ctxPath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}

	svc.handleRestartContext()

	if got := readTaskRow(t, dbPath, "rc-bad"); got.status != "executing" {
		t.Errorf("status = %q, want executing (unparseable context must not resolve the task)", got.status)
	}
	if _, err := os.Stat(ctxPath); !os.IsNotExist(err) {
		t.Error("malformed restart context should still be removed so it is not retried forever")
	}
}

func TestHandleRestartContext_StoreFailure_DoesNotPanic(t *testing.T) {
	svc, _ := newPollingFixture(t, &fakeTaskClient{})
	if err := restartctx.Write(restartctx.PathFor(svc.cfg.Path), restartctx.Context{TaskID: "x", Reason: "device-reboot"}); err != nil {
		t.Fatal(err)
	}
	_ = svc.store.Close()

	svc.handleRestartContext()
}

// ── PollAndStoreTasks ────────────────────────────────────────────────────────

func TestPollAndStoreTasks_ConnectivityFailure_SkipsRemoteCalls(t *testing.T) {
	client := &fakeTaskClient{}
	svc, _ := newPollingFixture(t, client)
	offline := errors.New("no route to host")
	svc.connectivityChecker = failingConnectivity{err: offline}

	err := svc.PollAndStoreTasks(context.Background())
	if !errors.Is(err, offline) {
		t.Fatalf("err = %v, want wrapping %v", err, offline)
	}
	if client.getCalls != 0 || len(client.recorded()) != 0 {
		t.Errorf("no RPC may be made while offline (GetTasks=%d, UpdateTask=%d)", client.getCalls, len(client.recorded()))
	}
}

// One poll cycle exercises every maintenance step: an interrupted task is
// failed and synced, an old failed task is reported as retrying and reset to
// assigned, and newly polled tasks are stored.
func TestPollAndStoreTasks_FullCycle(t *testing.T) {
	client := &fakeTaskClient{
		tasks: []taskstore.Task{{ID: "new-1", Slug: "s"}},
	}
	svc, dbPath := newPollingFixture(t, client)
	seedTasks(t, svc,
		taskstore.Task{ID: "interrupted", Status: "executing"},
		taskstore.Task{ID: "old-failed", Status: "failed"},
	)
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	execSQL(t, dbPath, `UPDATE tasks SET completed_at = ?, is_synced = 1 WHERE id = 'old-failed'`, old)

	if err := svc.PollAndStoreTasks(context.Background()); err != nil {
		t.Fatalf("PollAndStoreTasks: %v", err)
	}

	if got := readTaskRow(t, dbPath, "interrupted"); got.status != "failed" || !got.synced {
		t.Errorf("interrupted task = %+v, want failed and synced", got)
	}
	if got := readTaskRow(t, dbPath, "old-failed"); got.status != "assigned" {
		t.Errorf("old failed task status = %q, want assigned (reset for retry)", got.status)
	}
	if got := readTaskRow(t, dbPath, "new-1"); got.status != "assigned" {
		t.Errorf("polled task status = %q, want assigned", got.status)
	}

	got := map[string]taskUpdate{}
	for _, u := range client.recorded() {
		got[u.id] = u
	}
	wantRetry := taskUpdate{"old-failed", "retrying", fmt.Sprintf("Attempt 1 of %d failed; retrying.", store.MaxRetryAttempts+1)}
	if u := got["old-failed"]; u != wantRetry {
		t.Errorf("retry report = %+v, want %+v", u, wantRetry)
	}
	if u := got["interrupted"]; u.status != "failed" {
		t.Errorf("interrupted sync = %+v, want status failed", u)
	}
}

// A failed "retrying" report is logged only; the reset and poll still happen.
func TestPollAndStoreTasks_RetryingReportFails_StillResets(t *testing.T) {
	client := &fakeTaskClient{failState: map[string]bool{"retrying": true}}
	svc, dbPath := newPollingFixture(t, client)
	seedTasks(t, svc, taskstore.Task{ID: "old-failed", Status: "failed"})
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	execSQL(t, dbPath, `UPDATE tasks SET completed_at = ?, is_synced = 1 WHERE id = 'old-failed'`, old)

	if err := svc.PollAndStoreTasks(context.Background()); err != nil {
		t.Fatalf("PollAndStoreTasks: %v", err)
	}
	if got := readTaskRow(t, dbPath, "old-failed"); got.status != "assigned" {
		t.Errorf("status = %q, want assigned", got.status)
	}
	if client.getCalls != 1 {
		t.Errorf("GetTasks calls = %d, want 1", client.getCalls)
	}
}

// With the local store unusable every maintenance step fails and is logged;
// the poll itself still runs and the store error surfaces from StoreTasks.
func TestPollAndStoreTasks_StoreUnavailable(t *testing.T) {
	client := &fakeTaskClient{tasks: []taskstore.Task{{ID: "new-1"}}}
	svc, _ := newPollingFixture(t, client)
	_ = svc.store.Close()

	err := svc.PollAndStoreTasks(context.Background())
	if err == nil || !strings.Contains(err.Error(), "store tasks") {
		t.Fatalf("err = %v, want a 'store tasks' error", err)
	}
	if client.getCalls != 1 {
		t.Errorf("GetTasks calls = %d, want 1", client.getCalls)
	}
}

// ── SyncPendingTasks ─────────────────────────────────────────────────────────

func TestSyncPendingTasks_StoreUnavailable_ReturnsError(t *testing.T) {
	svc, _ := newPollingFixture(t, &fakeTaskClient{})
	_ = svc.store.Close()

	err := svc.SyncPendingTasks(context.Background())
	if err == nil || !strings.Contains(err.Error(), "get unsynced tasks") {
		t.Fatalf("err = %v, want a 'get unsynced tasks' error", err)
	}
}

// A task that fails to sync stays unsynced for the next attempt and does not
// stop the others from syncing.
func TestSyncPendingTasks_PartialFailure(t *testing.T) {
	client := &fakeTaskClient{failIDs: map[string]bool{"bad": true}}
	svc, dbPath := newPollingFixture(t, client)
	seedTasks(t, svc,
		taskstore.Task{ID: "bad", Status: "success"},
		taskstore.Task{ID: "good", Status: "failed"},
	)

	if err := svc.SyncPendingTasks(context.Background()); err != nil {
		t.Fatalf("SyncPendingTasks: %v", err)
	}
	if readTaskRow(t, dbPath, "bad").synced {
		t.Error("task whose update failed must remain unsynced")
	}
	if !readTaskRow(t, dbPath, "good").synced {
		t.Error("task whose update succeeded must be marked synced")
	}
	if n := len(client.recorded()); n != 2 {
		t.Errorf("UpdateTask calls = %d, want 2", n)
	}
}
