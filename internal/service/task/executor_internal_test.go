package task

// White-box tests for unexported executor functions.
// Package task (not task_test) is required to access resolveTaskTimeout and cancelOverdueTasks.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
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
	script, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(all fallback): %v", err)
	}
	if script.remotePath != "/scripts/cross-platform.sh" {
		t.Errorf("path = %q, want /scripts/cross-platform.sh", script.remotePath)
	}
	if script.filename != "cross-platform.sh" {
		t.Errorf("name = %q, want cross-platform.sh", script.filename)
	}
}

func TestResolveScript_InlinePlatformScript(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{
				"filename": "disk-partition-inventory.ps1",
				"inline":   "Write-Host '__PARTITION_INVENTORY__ {}'",
			},
		},
	}
	s := &TaskExecutorService{}
	script, err := s.resolveScript(task)
	if err != nil {
		t.Fatalf("resolveScript(inline): %v", err)
	}
	if script.remotePath != "" {
		t.Errorf("remotePath = %q, want empty", script.remotePath)
	}
	if script.inline == "" {
		t.Error("inline script was discarded")
	}
	if script.filename != "disk-partition-inventory.ps1" {
		t.Errorf("filename = %q, want disk-partition-inventory.ps1", script.filename)
	}
}

func TestResolveScript_InlineRequiresSafeFilename(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			"all": map[string]interface{}{"inline": "echo hello"},
		},
	}
	s := &TaskExecutorService{}
	if _, err := s.resolveScript(task); err == nil {
		t.Error("expected missing inline filename to be rejected")
	}
}

func TestResolveScript_InlineSizeLimit(t *testing.T) {
	task := taskstore.Task{
		Scripts: map[string]interface{}{
			"all": map[string]interface{}{
				"filename": "script.sh",
				"inline":   strings.Repeat("x", maxInlineScriptBytes+1),
			},
		},
	}
	s := &TaskExecutorService{}
	if _, err := s.resolveScript(task); err == nil {
		t.Error("expected oversized inline script to be rejected")
	}
}

func TestMaterializeScript_WritesInlineBody(t *testing.T) {
	s := &TaskExecutorService{}
	want := "Write-Host '__PARTITION_INVENTORY__ {}'"
	path, err := s.materializeScript(context.Background(), t.TempDir(), resolvedTaskScript{
		inline:   want,
		filename: "disk-partition-inventory.ps1",
	})
	if err != nil {
		t.Fatalf("materializeScript(inline): %v", err)
	}
	if filepath.Base(path) != "disk-partition-inventory.ps1" {
		t.Fatalf("materialized filename = %q", filepath.Base(path))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read materialized inline script: %v", err)
	}
	if string(got) != want {
		t.Errorf("materialized body = %q, want %q", got, want)
	}
}

func TestMaterializeScriptRejectsHashMismatch(t *testing.T) {
	s := &TaskExecutorService{}
	_, err := s.materializeScript(context.Background(), t.TempDir(), resolvedTaskScript{
		inline: "echo tampered", filename: "script.sh", expectedSHA256: strings.Repeat("0", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "integrity verification failed") {
		t.Fatalf("expected integrity failure, got %v", err)
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
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if err := s.downloadScript(context.Background(), "path/to/script.sh", localPath, wantHash); err != nil {
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
		filepath.Join(t.TempDir(), "missing.sh"), "")
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
		filepath.Join(t.TempDir(), "script.sh"), "")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}
