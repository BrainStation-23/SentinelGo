package task

// White-box tests for the inventory sync after system scripts and the
// command_kind cross-check (#231).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/artifact"
	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/taskstore"
)

// syncRecorder replaces postScriptInventorySyncFn. For each call it records
// how many task results had been reported by then.
type syncRecorder struct {
	mu            sync.Mutex
	client        *fakeTaskClient
	reportsAtCall []int
	errs          []error // returned in order, then nil
}

func stubInventorySync(t *testing.T, client *fakeTaskClient, errs ...error) *syncRecorder {
	t.Helper()
	r := &syncRecorder{client: client, errs: errs}
	prev := postScriptInventorySyncFn
	postScriptInventorySyncFn = func(context.Context, *config.Config) (string, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.reportsAtCall = append(r.reportsAtCall, len(client.recorded()))
		if len(r.errs) > 0 {
			err := r.errs[0]
			r.errs = r.errs[1:]
			return "", err
		}
		return "inventory synced successfully", nil
	}
	t.Cleanup(func() { postScriptInventorySyncFn = prev })
	return r
}

func (r *syncRecorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reportsAtCall)
}

// exitScript is an inline script that exits with code.
func exitScript(code string) map[string]interface{} {
	if runtime.GOOS == "windows" {
		return map[string]interface{}{runtime.GOOS: map[string]interface{}{"filename": "run.cmd", "body": "@exit /b " + code + "\r\n"}}
	}
	return map[string]interface{}{runtime.GOOS: map[string]interface{}{"filename": "run.sh", "body": "exit " + code + "\n"}}
}

func kindScriptTask(id, kind, exitCode string) taskstore.Task {
	return taskstore.Task{ID: id, Slug: "usb-storage-disable", CommandKind: kind, Scripts: exitScript(exitCode)}
}

func nativeTask(id, slug string) taskstore.Task {
	return taskstore.Task{ID: id, Slug: slug, CommandKind: taskstore.CommandKindNative}
}

// runBatch stores tasks in order, runs one ExecutePendingTasks pass and
// returns the executor, the client and the number of post-script syncs.
func runBatch(t *testing.T, ctx context.Context, setup func(*TaskExecutorService), tasks ...taskstore.Task) (*TaskExecutorService, *fakeTaskClient, *syncRecorder) {
	t.Helper()
	isolateTempDir(t)
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, "")
	rec := stubInventorySync(t, client)
	s.nativeHandlers[syncInventorySlug] = func(context.Context, taskstore.Task) (string, error) {
		return "inventory synced successfully", nil
	}
	s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) { return "ok", nil }
	if setup != nil {
		setup(s)
	}
	base := time.Now().Add(-time.Hour)
	for i := range tasks {
		at := base.Add(time.Duration(i) * time.Second)
		tasks[i].AssignedAt = &at
	}
	seedTasks(t, s.pollingSvc, tasks...)
	s.ExecutePendingTasks(ctx)
	return s, client, rec
}

func TestInventorySync_SystemScriptRan(t *testing.T) {
	for _, code := range []string{"0", "3"} {
		t.Run("exit_"+code, func(t *testing.T) {
			_, client, rec := runBatch(t, context.Background(), nil, kindScriptTask("t1", taskstore.CommandKindSystem, code))
			if rec.calls() != 1 {
				t.Fatalf("syncs = %d, want 1", rec.calls())
			}
			// The task's status is reported before the sync.
			if rec.reportsAtCall[0] != 1 {
				t.Errorf("reports before sync = %d, want 1", rec.reportsAtCall[0])
			}
			if u := client.recorded(); len(u) != 1 {
				t.Errorf("reported %+v, want exactly one update", u)
			}
		})
	}
}

func TestInventorySync_SystemScriptTimedOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a killed cmd.exe can keep the temp dir busy past test cleanup")
	}
	tk := taskstore.Task{
		ID: "t1", Slug: "os-update", CommandKind: taskstore.CommandKindSystem,
		Payload: map[string]interface{}{"timeout_minutes": 0.002},
		Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"filename": "run.sh", "body": "exec sleep 5\n"}},
	}
	_, client, rec := runBatch(t, context.Background(), nil, tk)
	if u := client.recorded(); len(u) != 1 || u[0].status != "failed" {
		t.Fatalf("reported %+v, want one failed update", u)
	}
	if rec.calls() != 1 {
		t.Errorf("syncs = %d, want 1 after a script that started and timed out", rec.calls())
	}
}

func TestInventorySync_SeveralSystemScriptsShareOneSync(t *testing.T) {
	_, _, rec := runBatch(t, context.Background(), nil,
		kindScriptTask("t1", taskstore.CommandKindSystem, "0"),
		kindScriptTask("t2", taskstore.CommandKindSystem, "1"),
		kindScriptTask("t3", taskstore.CommandKindSystem, "0"),
	)
	if rec.calls() != 1 {
		t.Fatalf("syncs = %d, want 1", rec.calls())
	}
	if rec.reportsAtCall[0] != 3 {
		t.Errorf("reports before sync = %d, want all 3", rec.reportsAtCall[0])
	}
}

func TestInventorySync_NotForNormalOrUnknownKind(t *testing.T) {
	for _, kind := range []string{taskstore.CommandKindNormal, ""} {
		t.Run("kind_"+kind, func(t *testing.T) {
			_, _, rec := runBatch(t, context.Background(), nil, kindScriptTask("t1", kind, "0"))
			if rec.calls() != 0 {
				t.Errorf("syncs = %d, want 0", rec.calls())
			}
		})
	}
}

func TestInventorySync_NotWhenScriptNeverStarted(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)

	tests := map[string]taskstore.Task{
		"no script for this OS": {Scripts: map[string]interface{}{"plan9": map[string]interface{}{"body": "echo"}}},
		"invalid artifacts":     {Scripts: exitScript("0"), Artifacts: []artifact.Spec{{ID: "Bad ID"}}},
		"download error":        {Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"path": "x/run.sh"}}},
	}
	for name, tk := range tests {
		t.Run(name, func(t *testing.T) {
			tk.ID, tk.Slug, tk.CommandKind = "t1", "usb-storage-disable", taskstore.CommandKindSystem
			_, client, rec := runBatch(t, context.Background(), func(s *TaskExecutorService) {
				s.cfg.SupabaseURL = failing.URL
			}, tk)
			if u := client.recorded(); len(u) != 1 || u[0].status != "failed" {
				t.Fatalf("reported %+v, want one failed update", u)
			}
			if rec.calls() != 0 {
				t.Errorf("syncs = %d, want 0 when the script never started", rec.calls())
			}
		})
	}
}

func TestInventorySync_NativeSyncInventoryInBatch(t *testing.T) {
	t.Run("after the system script", func(t *testing.T) {
		_, _, rec := runBatch(t, context.Background(), nil,
			kindScriptTask("t1", taskstore.CommandKindSystem, "0"),
			nativeTask("t2", syncInventorySlug),
		)
		if rec.calls() != 0 {
			t.Errorf("syncs = %d, want 0: the native sync-inventory already ran last", rec.calls())
		}
	})
	t.Run("before the system script", func(t *testing.T) {
		_, _, rec := runBatch(t, context.Background(), nil,
			nativeTask("t1", syncInventorySlug),
			kindScriptTask("t2", taskstore.CommandKindSystem, "0"),
		)
		if rec.calls() != 1 {
			t.Errorf("syncs = %d, want 1", rec.calls())
		}
	})
	t.Run("failed native sync-inventory", func(t *testing.T) {
		_, _, rec := runBatch(t, context.Background(), func(s *TaskExecutorService) {
			s.nativeHandlers[syncInventorySlug] = func(context.Context, taskstore.Task) (string, error) {
				return "", errors.New("upload failed")
			}
		},
			kindScriptTask("t1", taskstore.CommandKindSystem, "0"),
			nativeTask("t2", syncInventorySlug),
		)
		if rec.calls() != 1 {
			t.Errorf("syncs = %d, want 1 when the native sync-inventory failed", rec.calls())
		}
	})
}

func TestInventorySync_NativeOnlyBatch(t *testing.T) {
	_, _, rec := runBatch(t, context.Background(), nil, nativeTask("t1", "test-native"), nativeTask("t2", syncInventorySlug))
	if rec.calls() != 0 {
		t.Errorf("syncs = %d, want 0", rec.calls())
	}
}

func TestInventorySync_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, rec := runBatch(t, ctx, func(s *TaskExecutorService) {
		s.nativeHandlers["test-cancel"] = func(context.Context, taskstore.Task) (string, error) {
			cancel()
			return "", nil
		}
	},
		kindScriptTask("t1", taskstore.CommandKindSystem, "0"),
		nativeTask("t2", "test-cancel"),
	)
	if rec.calls() != 0 {
		t.Errorf("syncs = %d, want 0 after shutdown started", rec.calls())
	}
}

func TestInventorySync_ErrorLeavesStatusesAlone(t *testing.T) {
	isolateTempDir(t)
	client := &fakeTaskClient{}
	s, dbPath := newExecutorFixture(t, client, "")
	rec := stubInventorySync(t, client, errors.New("collect failed"))
	seedTasks(t, s.pollingSvc, kindScriptTask("t1", taskstore.CommandKindSystem, "0"))

	s.ExecutePendingTasks(context.Background())

	if rec.calls() != 1 {
		t.Fatalf("syncs = %d, want 1", rec.calls())
	}
	if u := client.recorded(); len(u) != 1 || u[0].status != "success" {
		t.Errorf("reported %+v, want only the task's own success", u)
	}
	if got := readTaskRow(t, dbPath, "t1"); got.status != "success" {
		t.Errorf("stored status = %q, want success", got.status)
	}
}

type countingRefresher struct{ calls atomic.Int32 }

func (r *countingRefresher) RefreshToken(context.Context) (string, error) {
	r.calls.Add(1)
	return "new-token", nil
}

func TestInventorySync_RecoversFrom401(t *testing.T) {
	isolateTempDir(t)
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, "")
	refresher := &countingRefresher{}
	s.pollingSvc.SetTokenRefresher(refresher)
	rec := stubInventorySync(t, client, &supabase.APIError{Status: 401, Message: "JWT expired"})
	seedTasks(t, s.pollingSvc, kindScriptTask("t1", taskstore.CommandKindSystem, "0"))

	s.ExecutePendingTasks(context.Background())

	if refresher.calls.Load() != 1 {
		t.Errorf("session recoveries = %d, want 1", refresher.calls.Load())
	}
	if rec.calls() != 2 {
		t.Errorf("sync attempts = %d, want 2 (401 + one retry)", rec.calls())
	}
}

func TestRunTask_NativeKindWithoutHandler(t *testing.T) {
	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write([]byte("echo hi"))
	}))
	t.Cleanup(srv.Close)
	isolateTempDir(t)
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, srv.URL)
	tk := taskstore.Task{
		ID: "t1", Slug: "future-native", CommandKind: taskstore.CommandKindNative,
		Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"path": "x/run.sh"}},
	}
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)

	u := client.recorded()
	if len(u) != 1 || u[0].status != "failed" ||
		!strings.Contains(u[0].note, `native command "future-native" is not supported by this agent version`) {
		t.Errorf("reported %+v, want a failed 'not supported by this agent version' note", u)
	}
	if downloads.Load() != 0 {
		t.Errorf("downloaded %d scripts, want none", downloads.Load())
	}
}

func TestRunTask_KindMismatchRunsNativeAndWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, "")
	var runs int
	s.nativeHandlers["firewall-enable"] = func(context.Context, taskstore.Task) (string, error) {
		runs++
		return "enabled", nil
	}
	tk := taskstore.Task{ID: "t1", Slug: "firewall-enable", CommandKind: taskstore.CommandKindSystem}
	for i := 0; i < 2; i++ {
		if _, err := s.runTask(context.Background(), tk); err != nil {
			t.Fatalf("runTask: %v", err)
		}
	}
	if runs != 2 {
		t.Errorf("native handler ran %d times, want 2", runs)
	}
	if n := strings.Count(buf.String(), "runs it natively"); n != 1 {
		t.Errorf("mismatch warning logged %d times, want 1", n)
	}
}

func TestScriptLaunched(t *testing.T) {
	exitErr := &exec.ExitError{ProcessState: &os.ProcessState{}}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"clean exit", nil, true},
		{"non-zero exit", exitErr, true},
		{"wrapped exit", fmt.Errorf("script: %w", exitErr), true},
		{"wait delay", exec.ErrWaitDelay, true},
		{"missing interpreter", errors.New("PowerShell (pwsh) is not installed on this device"), false},
		{"start failed", &os.PathError{Op: "fork/exec", Path: "/nope", Err: os.ErrNotExist}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scriptLaunched(tt.err); got != tt.want {
				t.Errorf("scriptLaunched(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
