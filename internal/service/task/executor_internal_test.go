package task

// White-box tests for unexported executor functions.
// Package task (not task_test) is required to access resolveTaskTimeout and cancelOverdueTasks.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/taskstore"
)

func TestResolveTaskTimeout_Default(t *testing.T) {
	task := taskstore.Task{Payload: map[string]interface{}{}}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout with no payload: got %v, want %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_FromPayload(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(60)},
	}
	got := resolveTaskTimeout(task)
	if got != 60*time.Minute {
		t.Errorf("resolveTaskTimeout(60 min): got %v, want %v", got, 60*time.Minute)
	}
}

func TestResolveTaskTimeout_CappedAtMax(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(9999)},
	}
	got := resolveTaskTimeout(task)
	if got != maxTaskTimeout {
		t.Errorf("resolveTaskTimeout(9999 min): got %v, want %v (maxTaskTimeout)", got, maxTaskTimeout)
	}
}

func TestResolveTaskTimeout_ZeroUsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(0)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(0): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_NegativeUsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(-5)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(-5): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_FractionalMinutes(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": float64(0.5)},
	}
	got := resolveTaskTimeout(task)
	if got != 30*time.Second {
		t.Errorf("resolveTaskTimeout(0.5 min): got %v, want 30s", got)
	}
}

func TestResolveTaskTimeout_WrongType_UsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"timeout_minutes": "not-a-number"},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(string value): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestResolveTaskTimeout_MissingKey_UsesDefault(t *testing.T) {
	task := taskstore.Task{
		Payload: map[string]interface{}{"something_else": float64(10)},
	}
	got := resolveTaskTimeout(task)
	if got != defaultTaskTimeout {
		t.Errorf("resolveTaskTimeout(missing key): got %v, want default %v", got, defaultTaskTimeout)
	}
}

func TestCancelOverdueTasks_CancelsStuckTask(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}

	cancelled := make(chan struct{}, 1)
	ctx, cancelFn := context.WithCancel(context.Background())
	_ = ctx

	// Wrap the real cancel to detect it was called.
	wrappedCancel := func() {
		cancelled <- struct{}{}
		cancelFn()
	}

	// Set deadline in the past (past deadline + grace).
	pastDeadline := time.Now().Add(-(watchdogGrace + time.Second))
	s.activeRunning["stuck-task"] = activeTask{cancel: wrappedCancel, deadline: pastDeadline}

	s.cancelOverdueTasks()

	select {
	case <-cancelled:
		// correct: stuck task was cancelled
	default:
		t.Error("cancelOverdueTasks should have cancelled the stuck task")
	}
}

func TestCancelOverdueTasks_DoesNotCancelActiveTask(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}

	cancelled := false
	// Set deadline in the future.
	futureDeadline := time.Now().Add(10 * time.Minute)
	s.activeRunning["active-task"] = activeTask{
		cancel:   func() { cancelled = true },
		deadline: futureDeadline,
	}

	s.cancelOverdueTasks()

	if cancelled {
		t.Error("cancelOverdueTasks must not cancel a task that is within its deadline + grace period")
	}
}

func TestCancelOverdueTasks_EmptyMap(t *testing.T) {
	s := &TaskExecutorService{
		activeRunning: make(map[string]activeTask),
	}
	// Should not panic on empty map.
	s.cancelOverdueTasks()
}

func TestRegisterAndDeregisterRunning(t *testing.T) {
	s := &TaskExecutorService{
		activeMu:      sync.Mutex{},
		activeRunning: make(map[string]activeTask),
	}

	deadline := time.Now().Add(5 * time.Minute)
	s.registerRunning("task-1", func() {}, deadline)

	s.activeMu.Lock()
	if _, ok := s.activeRunning["task-1"]; !ok {
		t.Error("registerRunning should add task to activeRunning")
	}
	s.activeMu.Unlock()

	s.deregisterRunning("task-1")

	s.activeMu.Lock()
	if _, ok := s.activeRunning["task-1"]; ok {
		t.Error("deregisterRunning should remove task from activeRunning")
	}
	s.activeMu.Unlock()
}

func TestRegisterRunning_ConcurrentSafety(t *testing.T) {
	s := &TaskExecutorService{
		activeMu:      sync.Mutex{},
		activeRunning: make(map[string]activeTask),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := string(rune('a' + id))
			s.registerRunning(key, func() {}, time.Now().Add(time.Minute))
			s.deregisterRunning(key)
		}(i)
	}
	wg.Wait()
}

// ── resolveScript ─────────────────────────────────────────────────────────────

// TestResolveScript_AllFallback verifies the "all" key is used when there is no
// platform-specific entry.
func TestResolveScript_AllFallback(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			"all": map[string]interface{}{"path": "/scripts/cross-platform.sh"},
		},
	}
	s := &TaskExecutorService{}
	ref, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(all fallback): %v", err)
	}
	if ref.RemotePath != "/scripts/cross-platform.sh" {
		t.Errorf("RemotePath = %q, want /scripts/cross-platform.sh", ref.RemotePath)
	}
	if ref.Filename != "cross-platform.sh" {
		t.Errorf("Filename = %q, want cross-platform.sh", ref.Filename)
	}
	if ref.Body != nil {
		t.Error("Body should be nil for path-based entry")
	}
}

// TestResolveScript_NoMatch verifies an error is returned when no script key
// matches the current platform and there is no "all" fallback.
func TestResolveScript_NoMatch(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			"plan9": map[string]interface{}{"path": "/scripts/plan9.sh"},
		},
	}
	s := &TaskExecutorService{}
	_, err := s.resolveScript(task)
	if err == nil {
		t.Error("expected error for no matching script platform, got nil")
	}
}

// TestResolveScript_EmptyScripts verifies an error is returned for an empty
// scripts map.
func TestResolveScript_EmptyScripts(t *testing.T) {
	task := taskstore.Task{Scripts: map[string]interface{}{}}
	s := &TaskExecutorService{}
	_, err := s.resolveScript(task)
	if err == nil {
		t.Error("expected error for empty scripts map, got nil")
	}
}

// TestResolveScript_InlineBodyOnly verifies an inline body-only entry is
// resolved correctly and gets a default filename on the current platform.
func TestResolveScript_InlineBodyOnly(t *testing.T) {
	body := "echo hello"
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{"body": body},
		},
	}
	s := &TaskExecutorService{}
	ref, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(inline body): %v", err)
	}
	if ref.Body == nil || *ref.Body != body {
		t.Errorf("Body = %v, want %q", ref.Body, body)
	}
	if ref.RemotePath != "" {
		t.Errorf("RemotePath = %q, want empty string", ref.RemotePath)
	}
	wantFilename := defaultScriptFilename()
	if ref.Filename != wantFilename {
		t.Errorf("Filename = %q, want %q", ref.Filename, wantFilename)
	}
}

// TestResolveScript_InlineBodyWithFilename verifies that an explicit filename
// in the entry is used when present.
func TestResolveScript_InlineBodyWithFilename(t *testing.T) {
	body := "echo hi"
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{
				"body":     body,
				"filename": "deploy.sh",
			},
		},
	}
	s := &TaskExecutorService{}
	ref, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(inline body+filename): %v", err)
	}
	if ref.Filename != "deploy.sh" {
		t.Errorf("Filename = %q, want deploy.sh", ref.Filename)
	}
}

// TestResolveScript_PathWinsOverBody verifies that when both "path" and "body"
// are present, "path" takes precedence (contract §2).
func TestResolveScript_PathWinsOverBody(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{
				"path":     "commands/install.sh",
				"body":     "echo should-be-ignored",
				"filename": "install.sh",
			},
		},
	}
	s := &TaskExecutorService{}
	ref, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(path+body): %v", err)
	}
	if ref.RemotePath != "commands/install.sh" {
		t.Errorf("RemotePath = %q, want commands/install.sh", ref.RemotePath)
	}
	if ref.Body != nil {
		t.Error("Body must be nil when path is present")
	}
}

// TestResolveScript_AllFallbackInlineBody verifies the "all" key also works
// with an inline body.
func TestResolveScript_AllFallbackInlineBody(t *testing.T) {
	body := "echo cross-platform"
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			"all": map[string]interface{}{
				"body":     body,
				"filename": "run.sh",
			},
		},
	}
	s := &TaskExecutorService{}
	ref, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(all+inline body): %v", err)
	}
	if ref.Body == nil || *ref.Body != body {
		t.Errorf("Body = %v, want %q", ref.Body, body)
	}
	if ref.Filename != "run.sh" {
		t.Errorf("Filename = %q, want run.sh", ref.Filename)
	}
}

// ── validateScriptFilename ────────────────────────────────────────────────────

func TestValidateScriptFilename_BadNames(t *testing.T) {
	bad := []string{
		"../etc/passwd",
		"../../x",
		"con:",
		"",
		".",
		"..",
		string(make([]byte, 129)), // too long
		"has/slash.sh",
		"has\x00null.sh",
	}
	for _, name := range bad {
		if err := validateScriptFilename(name); err == nil {
			t.Errorf("validateScriptFilename(%q) = nil, want error", name)
		}
	}
}

func TestValidateScriptFilename_GoodNames(t *testing.T) {
	good := []string{
		"install.ps1",
		"install.sh",
		"My Script 1.sh",
		"script-v2.py",
		"script_v2.py",
		"a",
		string(make([]byte, 128)), // max length (all zero bytes are invalid in regex, use a valid one)
	}
	// Replace the 128-byte test with a valid 128-char name
	good[len(good)-1] = string(bytes.Repeat([]byte("a"), 128))
	for _, name := range good {
		if err := validateScriptFilename(name); err != nil {
			t.Errorf("validateScriptFilename(%q) = %v, want nil", name, err)
		}
	}
}

// ── writeInlineScript ─────────────────────────────────────────────────────────

func TestWriteInlineScript_Success(t *testing.T) {
	body := "#!/bin/sh\necho hello"
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := writeInlineScript(path, body); err != nil {
		t.Fatalf("writeInlineScript: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}
}

func TestWriteInlineScript_OversizedBody(t *testing.T) {
	body := string(bytes.Repeat([]byte("x"), maxScriptBytes+1))
	path := filepath.Join(t.TempDir(), "big.sh")
	err := writeInlineScript(path, body)
	if err == nil {
		t.Fatal("expected error for oversized inline body, got nil")
	}
}

// ── downloadScript ────────────────────────────────────────────────────────────

// TestDownloadScript_Success verifies that a 200 response body is written to
// the local path.
func TestDownloadScript_Success(t *testing.T) {
	content := "#!/bin/bash\necho hello"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	s := &TaskExecutorService{cfg: cfg, client: &http.Client{}}

	localPath := filepath.Join(t.TempDir(), "script.sh")
	if err := s.downloadScript(context.Background(), "path/to/script.sh", localPath); err != nil {
		t.Fatalf("downloadScript: %v", err)
	}
	got, _ := os.ReadFile(localPath)
	if string(got) != content {
		t.Errorf("downloaded content = %q, want %q", got, content)
	}
}

// TestDownloadScript_NotFound verifies that a 404 response returns an error.
func TestDownloadScript_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL}
	s := &TaskExecutorService{cfg: cfg, client: &http.Client{}}

	err := s.downloadScript(context.Background(), "missing.sh",
		filepath.Join(t.TempDir(), "missing.sh"))
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

// TestDownloadScript_ServerError verifies that a 500 response returns an error.
func TestDownloadScript_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL}
	s := &TaskExecutorService{cfg: cfg, client: &http.Client{}}

	err := s.downloadScript(context.Background(), "script.sh",
		filepath.Join(t.TempDir(), "script.sh"))
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

// TestDownloadScript_RejectsOversizedScript: a script over the limit used to
// be truncated by io.LimitReader and then executed. It must now fail, and
// leave nothing behind to run.
func TestDownloadScript_RejectsOversizedScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("#"), maxScriptBytes+1))
	}))
	defer srv.Close()

	s := &TaskExecutorService{cfg: &config.Config{SupabaseURL: srv.URL}, client: &http.Client{}}
	localPath := filepath.Join(t.TempDir(), "big.sh")
	err := s.downloadScript(context.Background(), "big.sh", localPath)
	if !errors.Is(err, supabase.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Errorf("oversized script was left on disk (stat err = %v)", statErr)
	}
}

// TestDownloadScript_PathByteIdentical pins the command-scripts URL.
func TestDownloadScript_PathByteIdentical(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_, _ = w.Write([]byte("echo ok"))
	}))
	defer srv.Close()

	s := &TaskExecutorService{cfg: &config.Config{SupabaseURL: srv.URL}, client: &http.Client{}}
	if err := s.downloadScript(context.Background(), "commands/9668bfbe/linux.sh", filepath.Join(t.TempDir(), "s.sh")); err != nil {
		t.Fatal(err)
	}
	if want := "/storage/v1/object/authenticated/command-scripts/commands/9668bfbe/linux.sh"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}
