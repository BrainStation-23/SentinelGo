package task

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/taskstore"
)

func writeResult(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadTaskResult_MergesAndOverridesExitCode(t *testing.T) {
	p := writeResult(t, `{"exit_code": 0, "reboot_required": true, "message": "installed", "data": {"version": "6.1.2"}, "big": 12345678901234567890}`)
	note, got := readTaskResult(p, "output", nil)
	if note != "output" {
		t.Errorf("note = %q, want it unchanged", note)
	}
	if got["exit_code"] != 0 || got["reboot_required"] != true || got["message"] != "installed" {
		t.Errorf("result = %v", got)
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"big":12345678901234567890`) {
		t.Errorf("large integer not kept exactly: %s", b)
	}
}

func TestReadTaskResult_ScriptCannotSetExitCode(t *testing.T) {
	p := writeResult(t, `{"exit_code": 0}`)
	_, got := readTaskResult(p, "", exitError(t, 3))
	if got["exit_code"] != 3 {
		t.Errorf("exit_code = %v, want the process's 3", got["exit_code"])
	}
}

func TestReadTaskResult_Fallbacks(t *testing.T) {
	big := `{"data":"` + strings.Repeat("x", maxResultFileBytes) + `"}`
	tests := []struct {
		name     string
		content  *string
		wantNote string
	}{
		{"missing", nil, ""},
		{"invalid json", strPtr(`{"exit_code":`), "not valid JSON"},
		{"array", strPtr(`[1,2]`), "not a JSON object"},
		{"null", strPtr(`null`), "not a JSON object"},
		{"empty", strPtr(``), "not valid JSON"},
		{"oversize", &big, "16395 bytes, over the 16384 byte limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "result.json")
			if tt.content != nil {
				p = writeResult(t, *tt.content)
			}
			note, got := readTaskResult(p, "out", nil)
			if len(got) != 1 || got["exit_code"] != 0 {
				t.Errorf("result = %v, want only exit_code 0", got)
			}
			if tt.wantNote == "" && note != "out" {
				t.Errorf("note = %q, want it unchanged", note)
			}
			if tt.wantNote != "" && !strings.Contains(note, "[agent] result file ignored: "+tt.wantNote) {
				t.Errorf("note = %q, want it to mention %q", note, tt.wantNote)
			}
		})
	}
}

func TestReadTaskResult_NotRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "result.json")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	note, got := readTaskResult(p, "", nil)
	if len(got) != 1 || !strings.Contains(note, "not a regular file") {
		t.Errorf("result %v, note %q; want a directory ignored", got, note)
	}
}

func TestReadTaskResult_NoExitCodeNoResult(t *testing.T) {
	p := writeResult(t, `{"message":"x"}`)
	if _, got := readTaskResult(p, "", errors.New("exec: not started")); got != nil {
		t.Errorf("result = %v, want nil when the script never ran", got)
	}
}

func strPtr(s string) *string { return &s }

// exitError runs a command that exits with code, to get a real *exec.ExitError.
func exitError(t *testing.T, code int) error {
	t.Helper()
	name, body := echoScript("x", code)
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (&TaskExecutorService{}).executeLocalScript(context.Background(), p, "", nil)
	if c, ok := exitCode(err); !ok || c != code {
		t.Fatalf("setup: exit = %d, %v (err %v)", c, ok, err)
	}
	return err
}

// resultClient records structured results, like taskstore.Client.
type resultClient struct {
	*fakeTaskClient
	mu      sync.Mutex
	results []map[string]interface{}
	fail    int // fail this many UpdateTaskWithResult calls first
}

func (c *resultClient) UpdateTaskWithResult(ctx context.Context, id, status, note string, result map[string]interface{}) error {
	c.mu.Lock()
	failNow := c.fail > 0
	if failNow {
		c.fail--
	}
	c.results = append(c.results, result)
	c.mu.Unlock()
	if failNow {
		return errors.New("network down")
	}
	return c.UpdateTask(ctx, id, status, note)
}

func (c *resultClient) recordedResults() []map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]interface{}{}, c.results...)
}

func resultScript() (name, body string) {
	if runtime.GOOS == "windows" {
		return "result.cmd", "@echo installing\r\n" +
			"@echo {\"reboot_required\":true,\"exit_code\":0} > \"%SENTINEL_RESULT_FILE%\"\r\n" +
			"@exit /b 3\r\n"
	}
	return "result.sh", "echo installing\n" +
		"echo '{\"reboot_required\":true,\"exit_code\":0}' > \"$SENTINEL_RESULT_FILE\"\n" +
		"exit 3\n"
}

func scriptResultTask() taskstore.Task {
	name, body := resultScript()
	return taskstore.Task{ID: "t1", Slug: "install", Scripts: map[string]interface{}{
		runtime.GOOS: map[string]interface{}{"filename": name, "body": body},
	}}
}

// TestExecuteTask_ReportsStructuredResult runs a script that writes a result
// file and exits 3: the report carries the file's keys with the real exit code.
func TestExecuteTask_ReportsStructuredResult(t *testing.T) {
	isolateTempDir(t)
	client := &resultClient{fakeTaskClient: &fakeTaskClient{}}
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	s.pollingSvc.client = client
	tk := scriptResultTask()
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)

	res := client.recordedResults()
	if len(res) != 1 {
		t.Fatalf("results = %v, want 1", res)
	}
	if res[0]["exit_code"] != 3 || res[0]["reboot_required"] != true {
		t.Errorf("result = %v, want exit_code 3 and reboot_required", res[0])
	}
	if u := client.recorded(); len(u) != 1 || u[0].status != "failed" || !strings.Contains(u[0].note, "installing") {
		t.Errorf("updates = %+v", u)
	}
}

// TestSyncPendingTasks_ResendsResult: a report that failed on the network is
// retried with its result from the local store.
func TestSyncPendingTasks_ResendsResult(t *testing.T) {
	isolateTempDir(t)
	client := &resultClient{fakeTaskClient: &fakeTaskClient{}, fail: 1}
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	s.pollingSvc.client = client
	tk := scriptResultTask()
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)
	if err := s.pollingSvc.SyncPendingTasks(context.Background()); err != nil {
		t.Fatalf("SyncPendingTasks: %v", err)
	}

	res := client.recordedResults()
	if len(res) != 2 {
		t.Fatalf("results = %v, want the failed report and the resend", res)
	}
	// The resend comes from SQLite, so numbers are float64 after the round trip.
	if res[1]["exit_code"] != float64(3) || res[1]["reboot_required"] != true {
		t.Errorf("resent result = %v", res[1])
	}
}

func TestExecuteTask_NativeHandler_NoResult(t *testing.T) {
	client := &resultClient{fakeTaskClient: &fakeTaskClient{}}
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	s.pollingSvc.client = client
	s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) { return "ok", nil }
	tk := taskstore.Task{ID: "t1", Slug: "test-native"}
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)

	if res := client.recordedResults(); len(res) != 0 {
		t.Errorf("results = %v, want none for a native task", res)
	}
	if u := client.recorded(); len(u) != 1 {
		t.Errorf("updates = %+v, want 1 plain update", u)
	}
}

// TestReadTaskResult_CapIncludesExitCode: a file just under 16 KiB is fine on
// its own, but adding exit_code would push p_result over the backend's cap.
func TestReadTaskResult_CapIncludesExitCode(t *testing.T) {
	prefix, suffix := `{"data":"`, `"}`
	body := prefix + strings.Repeat("x", maxResultFileBytes-len(prefix)-len(suffix)) + suffix
	p := writeResult(t, body)
	note, got := readTaskResult(p, "out", nil)
	if len(got) != 1 || got["exit_code"] != 0 {
		t.Errorf("result keys = %d, want only exit_code", len(got))
	}
	if !strings.Contains(note, "once exit_code is added") {
		t.Errorf("note = %q", note)
	}
}
