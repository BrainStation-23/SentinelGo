package task

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/taskstore"
)

const (
	defaultTaskTimeout   = 30 * time.Minute
	maxTaskTimeout       = 24 * time.Hour
	watchdogInterval     = 2 * time.Minute
	watchdogGrace        = 5 * time.Minute
	maxInlineScriptBytes = 2 * 1024 * 1024
)

type resolvedTaskScript struct {
	remotePath     string
	inline         string
	filename       string
	expectedSHA256 string
}

// activeTask tracks an in-flight task for the watchdog.
type activeTask struct {
	cancel   context.CancelFunc
	deadline time.Time
}

// TaskExecutorService handles the execution of tasks assigned to the agent.
type TaskExecutorService struct {
	cfg            *config.Config
	pollingSvc     *TaskPollingService
	client         *http.Client
	runningTasks   map[string]bool
	nativeHandlers map[string]NativeTaskHandler

	activeMu      sync.Mutex
	activeRunning map[string]activeTask // task ID → {cancel, deadline}
}

// NewTaskExecutorService creates a new task execution service.
func NewTaskExecutorService(cfg *config.Config, pollingSvc *TaskPollingService) *TaskExecutorService {
	s := &TaskExecutorService{
		cfg:           cfg,
		pollingSvc:    pollingSvc,
		client:        httpx.NewClient(2 * time.Minute),
		runningTasks:  make(map[string]bool),
		activeRunning: make(map[string]activeTask),
	}
	s.registerNativeHandlers()
	return s
}

// RunExecutionLoop starts a loop that checks for and executes assigned tasks.
func (s *TaskExecutorService) RunExecutionLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ExecutePendingTasks(ctx)
		}
	}
}

// RunWatchdog polls activeRunning every watchdogInterval and cancels any task
// that has been running past its deadline plus watchdogGrace. The cancelled
// context fires taskCtx.Done() in runTask, which uses the existing timeout
// machinery to mark the task failed and report it to the server.
func (s *TaskExecutorService) RunWatchdog(ctx context.Context) {
	log.Printf("Watchdog: started (interval=%v, grace=%v)", watchdogInterval, watchdogGrace)
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Watchdog: stopped")
			return
		case <-ticker.C:
			s.cancelOverdueTasks()
		}
	}
}

func (s *TaskExecutorService) cancelOverdueTasks() {
	now := time.Now()
	s.activeMu.Lock()
	defer s.activeMu.Unlock()

	for id, t := range s.activeRunning {
		if now.After(t.deadline.Add(watchdogGrace)) {
			log.Printf("Watchdog: cancelling stuck task %s (deadline was %v ago)",
				id, now.Sub(t.deadline).Round(time.Second))
			t.cancel()
			// deregisterRunning will be called by the defer in runTask
		}
	}
}

func (s *TaskExecutorService) registerRunning(id string, cancel context.CancelFunc, deadline time.Time) {
	s.activeMu.Lock()
	s.activeRunning[id] = activeTask{cancel: cancel, deadline: deadline}
	s.activeMu.Unlock()
}

func (s *TaskExecutorService) deregisterRunning(id string) {
	s.activeMu.Lock()
	delete(s.activeRunning, id)
	s.activeMu.Unlock()
}

// ExecutePendingTasks finds locally stored 'assigned' tasks and runs them.
func (s *TaskExecutorService) ExecutePendingTasks(ctx context.Context) {
	tasks, err := s.pollingSvc.GetLocalTasks()
	fmt.Printf("Executor: Found %d local tasks to execute\n", len(tasks))
	if err != nil {
		log.Printf("Executor: Failed to get local tasks: %v", err)
		return
	}

	for _, task := range tasks {
		s.executeTask(ctx, task)
	}
}

// executeTask marks a single task as executing, runs it, and reports the result.
// Extracted from ExecutePendingTasks to keep complexity within the linter limit.
func (s *TaskExecutorService) executeTask(ctx context.Context, task taskstore.Task) {
	// Mark 'executing' in SQLite BEFORE running the script. If the agent is
	// killed mid-execution (e.g. by a reboot script), the task stays
	// 'executing' on disk. GetAssignedTasks only returns 'assigned' rows, so
	// it won't be re-picked on restart. ResetInterruptedTasks (called at
	// startup in PollAndStoreTasks) then moves it to 'failed (interrupted)'
	// and syncs it to the server. Skipping on error is intentional: if we
	// can't write the marker, executing would leave us in the unsafe state.
	if err := s.pollingSvc.MarkTaskExecuting(task.ID); err != nil {
		log.Printf("Executor: could not mark task %s as 'executing' — skipping to avoid unsafe re-execution: %v", task.ID, err)
		return
	}

	log.Printf("Executor: Starting task %s (%s)", task.ID, task.Slug)
	note, err := s.runTask(ctx, task)
	if err != nil {
		log.Printf("Executor: Task %s failed: %v", task.ID, err)
		statusNote := err.Error()
		if note != "" {
			statusNote = fmt.Sprintf("%s (Error: %v)", note, err)
		}
		if err := s.pollingSvc.ReportTaskStatus(ctx, task.ID, "failed", statusNote); err != nil {
			log.Printf("Executor: Failed to report task status: %v", err)
		}
		return
	}

	log.Printf("Executor: Task %s completed successfully", task.ID)
	statusNote := note
	if statusNote == "" {
		statusNote = "Executed successfully"
	}
	if err := s.pollingSvc.ReportTaskStatus(ctx, task.ID, "success", statusNote); err != nil {
		log.Printf("Executor: Failed to report task status: %v", err)
	}
}

// resolveTaskTimeout returns the timeout for a task. If the task payload
// contains a "timeout_minutes" key (float64 > 0), that value is used, capped
// at maxTaskTimeout. Otherwise defaultTaskTimeout applies.
func resolveTaskTimeout(task taskstore.Task) time.Duration {
	if v, ok := task.Payload["timeout_minutes"]; ok {
		if mins, ok := v.(float64); ok && mins > 0 {
			d := time.Duration(mins * float64(time.Minute))
			if d > maxTaskTimeout {
				d = maxTaskTimeout
			}
			return d
		}
	}
	return defaultTaskTimeout
}

func (s *TaskExecutorService) runTask(ctx context.Context, task taskstore.Task) (string, error) {
	timeout := resolveTaskTimeout(task)
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Register with the watchdog. If the task exceeds its deadline plus the
	// grace period the watchdog will call cancel(), firing taskCtx.Done() and
	// causing the select below (or the native handler) to return an error.
	s.registerRunning(task.ID, cancel, time.Now().Add(timeout))
	defer s.deregisterRunning(task.ID)

	if handler, ok := s.nativeHandlers[task.Slug]; ok {
		return handler(taskCtx, task)
	}

	script, err := s.resolveScript(task)
	if err != nil {
		return "", err
	}

	tempDir, err := os.MkdirTemp("", "sentinel-task-"+task.ID)
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Printf("Executor: Failed to remove temp dir: %v", err)
		}
	}()

	localScriptPath, err := s.materializeScript(taskCtx, tempDir, script)
	if err != nil {
		return "", err
	}

	payloadPath := filepath.Join(tempDir, "payload.json")
	payloadData, _ := json.Marshal(task.Payload)
	if err := os.WriteFile(payloadPath, payloadData, 0600); err != nil {
		return "", fmt.Errorf("write payload: %w", err)
	}

	// Buffer of 1 so the goroutine can always send even after a timeout, preventing a leak.
	resultChan := make(chan struct {
		output string
		err    error
	}, 1)

	go func() {
		output, err := s.executeLocalScript(taskCtx, localScriptPath, payloadPath)
		resultChan <- struct {
			output string
			err    error
		}{output, err}
	}()

	select {
	case <-taskCtx.Done():
		timeoutNote := fmt.Sprintf(
			"Task exceeded timeout of %v. Task ID: %s, Slug: %s. Forcefully stopped.",
			timeout.Round(time.Second), task.ID, task.Slug,
		)
		log.Printf("Executor: %s", timeoutNote)
		return timeoutNote, fmt.Errorf("task execution timeout")
	case result := <-resultChan:
		return result.output, result.err
	}
}

func (s *TaskExecutorService) resolveScript(task taskstore.Task) (resolvedTaskScript, error) {
	osKey := runtime.GOOS

	for _, key := range []string{osKey, "all"} {
		scriptObj, ok := task.Scripts[key].(map[string]interface{})
		if !ok {
			continue
		}

		if remotePath, ok := scriptObj["path"].(string); ok && remotePath != "" {
			filename := filepath.Base(remotePath)
			if configured, ok := scriptObj["filename"].(string); ok && configured != "" {
				filename = filepath.Base(configured)
			}
			if filename == "." || filename == string(filepath.Separator) {
				return resolvedTaskScript{}, fmt.Errorf("invalid script filename for platform: %s", key)
			}
			expectedSHA256, err := optionalScriptSHA256(scriptObj)
			if err != nil {
				return resolvedTaskScript{}, err
			}
			return resolvedTaskScript{remotePath: remotePath, filename: filename, expectedSHA256: expectedSHA256}, nil
		}

		if inline, ok := scriptObj["inline"].(string); ok && inline != "" {
			if len(inline) > maxInlineScriptBytes {
				return resolvedTaskScript{}, fmt.Errorf("inline script exceeds %d byte limit", maxInlineScriptBytes)
			}
			configured, _ := scriptObj["filename"].(string)
			filename := filepath.Base(configured)
			if configured == "" || filename == "." || filename == string(filepath.Separator) {
				return resolvedTaskScript{}, fmt.Errorf("inline script filename missing for platform: %s", key)
			}
			expectedSHA256, err := optionalScriptSHA256(scriptObj)
			if err != nil {
				return resolvedTaskScript{}, err
			}
			return resolvedTaskScript{inline: inline, filename: filename, expectedSHA256: expectedSHA256}, nil
		}
	}

	return resolvedTaskScript{}, fmt.Errorf("no script found for platform: %s", osKey)
}

func optionalScriptSHA256(scriptObj map[string]interface{}) (string, error) {
	raw, _ := scriptObj["sha256"].(string)
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "", nil // backward compatibility for already-queued tasks
	}
	if len(raw) != sha256.Size*2 {
		return "", fmt.Errorf("invalid script SHA-256 metadata")
	}
	for _, r := range raw {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", fmt.Errorf("invalid script SHA-256 metadata")
		}
	}
	return raw, nil
}

func verifyScriptSHA256(content []byte, expected string) error {
	if expected == "" {
		return nil
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(content))
	if actual != expected {
		return fmt.Errorf("script integrity verification failed")
	}
	return nil
}

func (s *TaskExecutorService) materializeScript(ctx context.Context, tempDir string, script resolvedTaskScript) (string, error) {
	localPath := filepath.Join(tempDir, script.filename)
	if script.inline != "" {
		if err := verifyScriptSHA256([]byte(script.inline), script.expectedSHA256); err != nil {
			return "", err
		}
		if err := os.WriteFile(localPath, []byte(script.inline), 0600); err != nil {
			return "", fmt.Errorf("write inline script: %w", err)
		}
		return localPath, nil
	}
	if err := s.downloadScript(ctx, script.remotePath, localPath, script.expectedSHA256); err != nil {
		return "", fmt.Errorf("download script: %w", err)
	}
	return localPath, nil
}

func (s *TaskExecutorService) downloadScript(ctx context.Context, remotePath, localPath, expectedSHA256 string) error {
	url := fmt.Sprintf("%s/storage/v1/object/authenticated/command-scripts/%s", s.cfg.SupabaseURL, remotePath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("apikey", s.cfg.SupabaseKey)
	req.Header.Set("Authorization", "Bearer "+s.cfg.GetAccessToken())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Executor: Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("script download returned HTTP %d", resp.StatusCode)
	}

	// #nosec G304 - localPath is a controlled path from task store
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("Executor: Failed to close output file: %v", err)
		}
	}()

	const maxScriptBytes = 10 * 1024 * 1024
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, maxScriptBytes+1))
	if err != nil {
		return err
	}
	if n > maxScriptBytes {
		_ = os.Remove(localPath)
		return fmt.Errorf("downloaded script exceeds %d byte limit", maxScriptBytes)
	}
	if expectedSHA256 != "" && fmt.Sprintf("%x", h.Sum(nil)) != expectedSHA256 {
		_ = os.Remove(localPath)
		return fmt.Errorf("script integrity verification failed")
	}
	return nil
}
