package task

// White-box tests for executeTask / runTask: native handlers, status notes,
// store failures, and the download-and-run script path against httptest.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// isolateTempDir points os.TempDir (used by runTask's os.MkdirTemp) at a test
// directory so script runs never write outside t.TempDir().
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, dir)
	}
	return dir
}

// newExecutorFixture wires an executor to a polling service backed by a temp
// database. srvURL may be empty when no script download is expected.
func newExecutorFixture(t *testing.T, client *fakeTaskClient, srvURL string) (*TaskExecutorService, string) {
	t.Helper()
	svc, dbPath := newPollingFixture(t, client)
	svc.cfg.SupabaseURL = srvURL
	return NewTaskExecutorService(svc.cfg, svc), dbPath
}

// scriptServer serves body for every storage download.
func scriptServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── executeTask ──────────────────────────────────────────────────────────────

func TestExecuteTask_NativeHandlerNotes(t *testing.T) {
	tests := []struct {
		name       string
		note       string
		err        error
		wantStatus string
		wantNote   string
	}{
		{"success with note", "rebooted", nil, "success", "rebooted"},
		{"success without note", "", nil, "success", "Executed successfully"},
		{"failure with note", "partial output", errors.New("boom"), "failed", "partial output (Error: boom)"},
		{"failure without note", "", errors.New("boom"), "failed", "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeTaskClient{}
			s, dbPath := newExecutorFixture(t, client, "")
			s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) {
				return tt.note, tt.err
			}
			tk := taskstore.Task{ID: "t1", Slug: "test-native"}
			seedTasks(t, s.pollingSvc, tk)

			s.executeTask(context.Background(), tk)

			got := readTaskRow(t, dbPath, "t1")
			if got.status != tt.wantStatus || got.note != tt.wantNote || !got.synced {
				t.Errorf("task = %+v, want {%s %q synced}", got, tt.wantStatus, tt.wantNote)
			}
			if u := client.recorded(); len(u) != 1 || u[0] != (taskUpdate{"t1", tt.wantStatus, tt.wantNote}) {
				t.Errorf("reported %+v, want one {t1 %s %q}", u, tt.wantStatus, tt.wantNote)
			}
		})
	}
}

// TestExecuteTask_NoteCapped: a huge note is cut to head + tail before it is
// reported or stored, and a reboot marker in the cut middle survives (#139).
func TestExecuteTask_NoteCapped(t *testing.T) {
	client := &fakeTaskClient{}
	s, dbPath := newExecutorFixture(t, client, "")
	huge := strings.Repeat("h", 1<<20) + "\n" + rebootMarker + "\n" + strings.Repeat("t", 4<<20) + "END"
	s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) {
		return huge, errors.New("installer failed")
	}
	tk := taskstore.Task{ID: "t1", Slug: "test-native"}
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)

	u := client.recorded()
	if len(u) != 1 {
		t.Fatalf("reported %d updates, want 1", len(u))
	}
	note := u[0].note
	if len(note) > maxNoteBytes+128 {
		t.Errorf("reported note is %d bytes, want about %d", len(note), maxNoteBytes)
	}
	if !strings.Contains(note, "END (Error: installer failed)") || !strings.Contains(note, rebootMarker) {
		t.Errorf("note lost its tail or the reboot marker")
	}
	if got := readTaskRow(t, dbPath, "t1"); got.note != note {
		t.Error("stored note differs from the reported note")
	}
}

// If the 'executing' marker can't be written the task must not run at all:
// running it could repeat a reboot forever after a crash.
func TestExecuteTask_MarkExecutingFails_SkipsTask(t *testing.T) {
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, "")
	ran := false
	s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) {
		ran = true
		return "", nil
	}
	_ = s.pollingSvc.store.Close()

	s.executeTask(context.Background(), taskstore.Task{ID: "t1", Slug: "test-native"})

	if ran {
		t.Error("task ran although it could not be marked executing")
	}
	if n := len(client.recorded()); n != 0 {
		t.Errorf("UpdateTask calls = %d, want 0", n)
	}
}

// A store failure while recording the result is logged, not fatal; the
// server still receives the result.
func TestExecuteTask_ReportStatusStoreFails(t *testing.T) {
	for _, handlerErr := range []error{nil, errors.New("boom")} {
		client := &fakeTaskClient{}
		s, _ := newExecutorFixture(t, client, "")
		s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) {
			_ = s.pollingSvc.store.Close() // the store dies mid-task
			return "", handlerErr
		}
		tk := taskstore.Task{ID: "t1", Slug: "test-native"}
		seedTasks(t, s.pollingSvc, tk)

		s.executeTask(context.Background(), tk)

		if n := len(client.recorded()); n != 1 {
			t.Errorf("handlerErr=%v: UpdateTask calls = %d, want 1", handlerErr, n)
		}
	}
}

func TestExecutePendingTasks_StoreUnavailable_DoesNotPanic(t *testing.T) {
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	_ = s.pollingSvc.store.Close()
	s.ExecutePendingTasks(context.Background())
}

// ── runTask ──────────────────────────────────────────────────────────────────

func TestRunTask_NoScriptForPlatform(t *testing.T) {
	isolateTempDir(t)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	_, err := s.runTask(context.Background(), taskstore.Task{ID: "t1", Slug: "scripted"})
	if err == nil || !strings.Contains(err.Error(), "no script found") {
		t.Fatalf("err = %v, want 'no script found'", err)
	}
}

func TestRunTask_DownloadFails_CleansUpTempDir(t *testing.T) {
	tmp := isolateTempDir(t)
	srv := scriptServer(t, http.StatusNotFound, "not found")
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	_, err := s.runTask(context.Background(), scriptTask("x.sh"))
	if err == nil || !strings.Contains(err.Error(), "download script") {
		t.Fatalf("err = %v, want 'download script' error", err)
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestRunTask_TempDirUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, missing)
	}
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")

	_, err := s.runTask(context.Background(), scriptTask("x.sh"))
	if err == nil || !strings.Contains(err.Error(), "create temp dir") {
		t.Fatalf("err = %v, want 'create temp dir' error", err)
	}
}

// echoScript returns a harmless script for the host's executeLocalScript:
// cmd on Windows, bash elsewhere. exitCode 0 means a clean exit.
func echoScript(text string, exitCode int) (name, body string) {
	if runtime.GOOS == "windows" {
		body = "@echo " + text + "\r\n"
		if exitCode != 0 {
			body += "@exit /b " + strconv.Itoa(exitCode) + "\r\n"
		}
		return "task.cmd", body
	}
	body = "echo " + text + "\n"
	if exitCode != 0 {
		body += "exit " + strconv.Itoa(exitCode) + "\n"
	}
	return "task.sh", body
}

func TestRunTask_ScriptSucceeds_ReturnsOutput(t *testing.T) {
	tmp := isolateTempDir(t)
	name, body := echoScript("hello-from-task", 0)
	srv := scriptServer(t, http.StatusOK, body)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	out, err := s.runTask(context.Background(), scriptTask(name))
	if err != nil {
		t.Fatalf("runTask: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "hello-from-task") {
		t.Errorf("output = %q, want it to contain hello-from-task", out)
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestRunTask_ScriptFails_ReturnsOutputAndError(t *testing.T) {
	isolateTempDir(t)
	name, body := echoScript("about-to-fail", 3)
	srv := scriptServer(t, http.StatusOK, body)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	out, err := s.runTask(context.Background(), scriptTask(name))
	if err == nil {
		t.Fatalf("runTask succeeded, want a non-zero exit error (output %q)", out)
	}
	if !strings.Contains(out, "about-to-fail") {
		t.Errorf("output = %q, want the script's output kept for the failure note", out)
	}
}

// TestRunTask_InlineBody_Runs runs a policy-style inline script with no
// storage path: nothing is downloaded and the output reaches the note (#135).
func TestRunTask_InlineBody_Runs(t *testing.T) {
	tmp := isolateTempDir(t)
	name, body := echoScript("hello-inline", 0)
	// No server: any download attempt would fail.
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "http://127.0.0.1:0")

	task := taskstore.Task{
		ID:   "t1",
		Slug: "install-package",
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{"filename": name, "content_type": "text/plain", "body": body},
		},
	}
	out, err := s.runTask(context.Background(), task)
	if err != nil {
		t.Fatalf("runTask: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "hello-inline") {
		t.Errorf("output = %q, want it to contain hello-inline", out)
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestRunTask_InlineBadFilename_NotRun(t *testing.T) {
	tmp := isolateTempDir(t)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	task := taskstore.Task{ID: "t1", Slug: "x", Scripts: map[string]interface{}{
		runtime.GOOS: map[string]interface{}{"filename": "../evil.sh", "body": "echo pwned"},
	}}
	if _, err := s.runTask(context.Background(), task); err == nil {
		t.Fatal("runTask succeeded, want a filename error")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(tmp), "evil.sh")); err == nil {
		t.Error("inline script was written outside the temp dir")
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestWriteInlineScript_Mode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "install.sh")
	if err := writeInlineScript(p, "echo hi\n"); err != nil {
		t.Fatalf("writeInlineScript: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "echo hi\n" {
		t.Fatalf("content = %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0700 {
			t.Errorf("mode = %v, want 0700", fi.Mode().Perm())
		}
	}
}

// scriptTask is a scripted task whose script for this OS is at commands/<name>.
func scriptTask(name string) taskstore.Task {
	return taskstore.Task{
		ID:      "t1",
		Slug:    "scripted",
		Payload: map[string]interface{}{"k": "v"},
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{"path": "commands/" + name},
		},
	}
}

func assertNoTaskTempDirs(t *testing.T, dir string) {
	t.Helper()
	left, _ := filepath.Glob(filepath.Join(dir, "sentinel-task-*"))
	if len(left) != 0 {
		t.Errorf("runTask left temp dirs behind: %v", left)
	}
}

// ── downloadScript ───────────────────────────────────────────────────────────

func TestDownloadScript_LocalPathUnwritable(t *testing.T) {
	s := &TaskExecutorService{cfg: &config.Config{SupabaseURL: "http://127.0.0.1:0"}, client: &http.Client{}}
	err := s.downloadScript(context.Background(), "x.sh", filepath.Join(t.TempDir(), "missing", "x.sh"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a not-exist error from creating the local file", err)
	}
}
