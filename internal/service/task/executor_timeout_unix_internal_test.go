//go:build !windows

package task

// The timeout branch of runTask, exercised with a real script that blocks
// until it is killed. Unix-only: `exec sleep` makes the killed process the
// one holding the output pipe, so cancellation is prompt. On Windows a cmd
// script's sleeping child outlives cmd and holds the pipe for WaitDelay.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunTask_CancelledWhileScriptRuns_ReportsTimeout(t *testing.T) {
	tmp := isolateTempDir(t)
	marker := filepath.Join(t.TempDir(), "started")
	// The script announces it has started, then blocks until killed.
	body := "echo started > '" + marker + "'\nexec sleep 30\n"
	srv := scriptServer(t, http.StatusOK, body)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Cancel only once the script is running, so the download and setup
		// steps are not what gets interrupted.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker); err == nil {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()

	start := time.Now()
	note, err := s.runTask(ctx, scriptTask("block.sh"))
	if err == nil || err.Error() != "task execution timeout" {
		t.Fatalf("err = %v, want 'task execution timeout' (note %q)", err, note)
	}
	if !strings.Contains(note, "Task exceeded timeout") || !strings.Contains(note, "Slug: scripted") {
		t.Errorf("note = %q, want the timeout note naming the task", note)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("runTask took %v after cancellation; the select should return immediately", elapsed)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Errorf("script never started (marker missing): %v", statErr)
	}
	assertNoTaskTempDirs(t, tmp)
}
