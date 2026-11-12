package internal

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/scheduler"
	tasksvc "sentinelgo/internal/service/task"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/scan"
)

// runYARAScanTask runs the yara-scan native task the way the task manager
// does and returns its error text.
func runYARAScanTask(t *testing.T) string {
	t.Helper()
	_, err := native.Find(yara.TaskScan).Run(context.Background(), nil,
		taskstore.Task{Payload: map[string]any{"preset": "quick"}})
	if err == nil {
		t.Fatal("yara-scan with no bundle should fail")
	}
	return err.Error()
}

// Startup order (#416): threat hunting is wired before the task manager
// starts, so a yara-scan task it picks up reaches the scanner; Stop unhooks
// it, stops the scan and workers and closes the queue.
func TestStart_YARAOrderAndShutdown(t *testing.T) {
	stubDefaultTasks(t)
	resetUpdaterRetrier(t)

	atTaskManager := make(chan string, 1)
	exited := make(chan struct{})
	origRun := runTaskManager
	runTaskManager = func(tm *tasksvc.TaskManager, ctx context.Context) error {
		atTaskManager <- runYARAScanTask(t)
		defer close(exited)
		return origRun(tm, ctx)
	}
	t.Cleanup(func() { runTaskManager = origRun })

	fb := newFakeBackend(t, http.StatusOK)
	cfg := startTestConfig(t, fb.srv.URL)
	cfg.EnableTaskPolling = true
	cfg.YARAEnabled = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mi := NewMainIntegration(cfg)
	if err := mi.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	select {
	case msg := <-atTaskManager:
		// The runner answered (no bundle yet), not the "not running" hook.
		if !strings.Contains(msg, scan.ErrDisabled.Error()) {
			t.Fatalf("yara-scan when the task manager starts: %s", msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("task manager not started")
	}
	y := mi.yara
	if y == nil || y.runner == nil || y.pool == nil || y.events == nil {
		t.Fatalf("YARA not started: %+v", y)
	}
	tasks := mi.scheduler.GetTaskStatus()
	for _, name := range []string{yara.TaskSync, yara.TaskScheduler, yara.TaskEventSync} {
		if _, ok := tasks[name]; !ok {
			t.Errorf("scheduler task %s missing", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfg.Path), scan.StatusFileName)); err != nil {
		t.Errorf("local status not written: %v", err)
	}

	if err := mi.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	<-exited
	if mi.yara != nil {
		t.Error("YARA state kept after Stop")
	}
	if msg := runYARAScanTask(t); !strings.Contains(msg, "not running") {
		t.Errorf("yara-scan after Stop: %s", msg)
	}
	if y.runner.Current() != nil {
		t.Error("scan running after Stop")
	}
	if _, _, _, err := y.events.Stats(); err == nil {
		t.Error("event queue still open after Stop")
	}
}

// yara_enabled false (#416): the sync still runs and reports disabled, and
// queued events still upload, but there is no worker, no scan scheduler and
// no yara-scan hook.
func TestStartYARA_LocallyDisabled(t *testing.T) {
	cfg := miTestConfig(t)
	cfg.YARAEnabled = false
	mi := NewMainIntegrationWith(cfg, scheduler.NewScheduler())
	mi.startYARA()
	t.Cleanup(func() { mi.stopYARA() })
	y := mi.yara
	if y == nil || y.pool != nil || y.runner != nil {
		t.Fatalf("workers or scans started: %+v", y)
	}
	tasks := mi.scheduler.GetTaskStatus()
	if _, ok := tasks[yara.TaskScheduler]; ok {
		t.Error("yara-scan-scheduler scheduled although yara_enabled is false")
	}
	for _, name := range []string{yara.TaskSync, yara.TaskEventSync} {
		if _, ok := tasks[name]; !ok {
			t.Errorf("%s not scheduled", name)
		}
	}
	if st := y.syncer.Status(); st.State != yara.StateDisabled {
		t.Errorf("status state %q, want disabled", st.State)
	}
	s := y.summary()
	if s.State != yara.StateDisabled || s.LocalEnabled || s.WorkersHealthy {
		t.Errorf("inventory summary %+v", s)
	}
	if msg := runYARAScanTask(t); !strings.Contains(msg, "not running") {
		t.Errorf("yara-scan with YARA off locally: %s", msg)
	}
	ls, err := scan.ReadStatus(filepath.Join(filepath.Dir(cfg.Path), scan.StatusFileName))
	if err != nil || ls.LocalEnabled || ls.Status.State != yara.StateDisabled {
		t.Fatalf("local status %+v, %v", ls, err)
	}
}

// YARA workers lower their own priority; the pool says so in their
// environment (#413). File DLP's pool doesn't.
func TestYARAPoolOptions_Background(t *testing.T) {
	o := yaraPoolOptions("sentinelgo")
	if o.Workers != 1 || len(o.Env) != 1 || o.Env[0] != scanworker.BackgroundEnv+"=1" {
		t.Fatalf("options %+v", o)
	}
}
