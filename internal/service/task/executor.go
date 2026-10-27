package task

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/artifact"
	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/taskstore"
)

const (
	defaultTaskTimeout = 30 * time.Minute
	maxTaskTimeout     = 24 * time.Hour
	watchdogInterval   = 2 * time.Minute
	watchdogGrace      = 5 * time.Minute
)

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

	kindWarned sync.Map // slug → struct{}: kind mismatch already logged
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

	// A system script usually changes the machine, so once the batch has run
	// one, inventory is sent right away instead of on the next agent-info
	// tick (#231). Several system scripts share one sync, and a native
	// sync-inventory task later in the batch makes it unnecessary.
	pendingInventorySync := false
	for _, task := range tasks {
		out := s.executeTask(ctx, task)
		switch {
		case out.scriptStarted && task.CommandKind == taskstore.CommandKindSystem:
			pendingInventorySync = true
		case out.succeeded && task.Slug == syncInventorySlug && s.isNative(task.Slug):
			pendingInventorySync = false
		}
	}
	if pendingInventorySync && ctx.Err() == nil {
		s.syncInventoryAfterSystemScripts(ctx)
	}
}

// syncInventorySlug is the native task that collects and uploads inventory.
const syncInventorySlug = "sync-inventory"

// postScriptInventorySyncFn runs the native sync-inventory handler; replaced
// in tests.
var postScriptInventorySyncFn = func(ctx context.Context, cfg *config.Config) (string, error) {
	h := native.Find(syncInventorySlug)
	if h == nil {
		return "", fmt.Errorf("no handler registered for slug %q", syncInventorySlug)
	}
	return h.Run(ctx, cfg, taskstore.Task{Slug: syncInventorySlug})
}

// syncInventoryAfterSystemScripts uploads inventory after a batch that ran a
// system script. Every task's status has already been reported, so a failure
// is only logged; the scheduled agent-info update sends it later anyway.
func (s *TaskExecutorService) syncInventoryAfterSystemScripts(ctx context.Context) {
	log.Printf("Executor: system script ran, syncing inventory")
	var note string
	err := s.authRetry(ctx, func() error {
		var err error
		note, err = postScriptInventorySyncFn(ctx, s.cfg)
		return err
	})
	if err != nil {
		log.Printf("Executor: inventory sync after system script failed: %v", err)
		return
	}
	log.Printf("Executor: inventory sync after system script: %s", note)
}

func (s *TaskExecutorService) isNative(slug string) bool {
	_, ok := s.nativeHandlers[slug]
	return ok
}

// taskOutcome is what ExecutePendingTasks needs to know about a task it ran.
type taskOutcome struct {
	// scriptStarted is true once the script process was launched, whatever
	// its exit; the machine may have changed.
	scriptStarted bool
	succeeded     bool
}

// executeTask marks a single task as executing, runs it, and reports the result.
// Extracted from ExecutePendingTasks to keep complexity within the linter limit.
func (s *TaskExecutorService) executeTask(ctx context.Context, task taskstore.Task) taskOutcome {
	// Mark 'executing' in SQLite BEFORE running the script. If the agent is
	// killed mid-execution (e.g. by a reboot script), the task stays
	// 'executing' on disk. GetAssignedTasks only returns 'assigned' rows, so
	// it won't be re-picked on restart. ResetInterruptedTasks (called at
	// startup in PollAndStoreTasks) then moves it to 'failed (interrupted)'
	// and syncs it to the server. Skipping on error is intentional: if we
	// can't write the marker, executing would leave us in the unsafe state.
	if err := s.pollingSvc.MarkTaskExecuting(task.ID); err != nil {
		log.Printf("Executor: could not mark task %s as 'executing' — skipping to avoid unsafe re-execution: %v", task.ID, err)
		return taskOutcome{}
	}

	log.Printf("Executor: Starting task %s (%s)", task.ID, task.Slug)
	note, result, scriptStarted, err := s.runTaskResult(ctx, task)
	if err != nil {
		log.Printf("Executor: Task %s failed: %v", task.ID, sanitize.ForLog(err.Error()))
		statusNote := err.Error()
		if note != "" {
			statusNote = fmt.Sprintf("%s (Error: %v)", note, err)
		}
		if err := s.pollingSvc.ReportTaskResult(ctx, task.ID, "failed", capNote(statusNote), result); err != nil {
			log.Printf("Executor: Failed to report task status: %v", err)
		}
		return taskOutcome{scriptStarted: scriptStarted}
	}

	log.Printf("Executor: Task %s completed successfully", task.ID)
	statusNote := note
	if statusNote == "" {
		statusNote = "Executed successfully"
	}
	if err := s.pollingSvc.ReportTaskResult(ctx, task.ID, "success", capNote(statusNote), result); err != nil {
		log.Printf("Executor: Failed to report task status: %v", err)
	}
	return taskOutcome{scriptStarted: scriptStarted, succeeded: true}
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
	note, _, _, err := s.runTaskResult(ctx, task)
	return note, err
}

// runTaskResult runs a task and returns its note, its structured result
// (nil unless a script ran to exit, #140), whether a script process was
// started (#231) and its error.
func (s *TaskExecutorService) runTaskResult(ctx context.Context, task taskstore.Task) (note string, result map[string]interface{}, scriptStarted bool, err error) {
	timeout := resolveTaskTimeout(task)
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Register with the watchdog. If the task exceeds its deadline plus the
	// grace period the watchdog will call cancel(), firing taskCtx.Done() and
	// causing the select below (or the native handler) to return an error.
	s.registerRunning(task.ID, cancel, time.Now().Add(timeout))
	defer s.deregisterRunning(task.ID)

	if handler, ok := s.nativeHandlers[task.Slug]; ok {
		s.warnKindMismatch(task)
		if len(task.Artifacts) > 0 {
			return "", nil, false, fmt.Errorf("artifacts are only supported for script tasks")
		}
		note, err := handler(taskCtx, task)
		return note, nil, false, err
	}
	if task.CommandKind == taskstore.CommandKindNative {
		// Without this the task fell through to the script path and failed
		// with a misleading "no script found for platform".
		return "", nil, false, fmt.Errorf("native command %q is not supported by this agent version (%s)", task.Slug, config.Version)
	}

	// Reject bad artifact specs before anything is created or downloaded.
	if err := artifact.Validate(task.Artifacts); err != nil {
		return "", nil, false, fmt.Errorf("invalid task artifacts: %w", err)
	}

	script, err := s.resolveScript(task)
	if err != nil {
		return "", nil, false, err
	}

	tempDir, err := os.MkdirTemp("", "sentinel-task-"+task.ID)
	if err != nil {
		return "", nil, false, fmt.Errorf("create temp dir: %w", err)
	}
	// Removes the script, payload.json and every artifact, whatever the
	// outcome (contract §3.7).
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Printf("Executor: Failed to remove temp dir: %v", err)
		}
	}()

	localScriptPath := filepath.Join(tempDir, script.Filename)
	if script.Body != nil {
		if err := writeInlineScript(localScriptPath, *script.Body); err != nil {
			return "", nil, false, fmt.Errorf("write inline script: %w", err)
		}
	} else if err := s.downloadScript(taskCtx, script.RemotePath, localScriptPath); err != nil {
		return "", nil, false, fmt.Errorf("download script: %w", err)
	}

	// Downloads run under taskCtx, so they count against the task timeout;
	// the backend sizes timeout_minutes to cover download plus install
	// (contract §4). If any file fails verification the script never runs.
	artifactsDir := filepath.Join(tempDir, "artifacts")
	artifactPaths, err := s.fetchArtifacts(taskCtx, artifactsDir, task.Artifacts)
	if err != nil {
		return "", nil, false, fmt.Errorf("fetch artifacts: %w", err)
	}

	payloadPath := filepath.Join(tempDir, "payload.json")
	if err := writePayload(payloadPath, task, artifactPaths); err != nil {
		return "", nil, false, err
	}
	resultPath := filepath.Join(tempDir, "result.json")
	env := append(scriptEnv(task, tempDir, artifactsDir, artifactPaths), "SENTINEL_RESULT_FILE="+resultPath)

	// Buffer of 1 so the goroutine can always send even after a timeout, preventing a leak.
	resultChan := make(chan struct {
		output string
		err    error
	}, 1)

	scriptStarted = true
	go func() {
		output, err := s.executeLocalScript(taskCtx, localScriptPath, payloadPath, env)
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
		return timeoutNote, nil, scriptStarted, fmt.Errorf("task execution timeout")
	case res := <-resultChan:
		note, taskResult := readTaskResult(resultPath, res.output, res.err)
		return note, taskResult, scriptStarted, res.err
	}
}

// fetchArtifacts downloads and verifies the task's artifacts into dir. A task
// without artifacts makes no request and gets a nil map.
func (s *TaskExecutorService) fetchArtifacts(ctx context.Context, dir string, specs []artifact.Spec) (map[string]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	c := supabase.FromConfig(s.cfg, supabase.WithHTTPClient(artifact.HTTPClient()))
	return artifact.Fetch(ctx, c, s.authRetry, dir, specs)
}

// authRetry recovers the session once on a 401, through the same path task
// status updates use.
func (s *TaskExecutorService) authRetry(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil || s.pollingSvc == nil || !s.pollingSvc.recoverAfter401(ctx, err) {
		return err
	}
	return fn()
}

// warnKindMismatch logs, once per slug, when the backend calls a command the
// agent runs natively "system" or "normal". The native handler still runs.
func (s *TaskExecutorService) warnKindMismatch(task taskstore.Task) {
	if task.CommandKind != taskstore.CommandKindSystem && task.CommandKind != taskstore.CommandKindNormal {
		return
	}
	if _, warned := s.kindWarned.LoadOrStore(task.Slug, struct{}{}); warned {
		return
	}
	log.Printf("Executor: backend marks %q as a %s command, but this agent runs it natively",
		sanitize.ForLog(task.Slug), sanitize.ForLog(task.CommandKind))
}

// artifactInfo is one entry of payload.json's reserved "artifacts" key.
type artifactInfo struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// writePayload writes the task payload for the script. With artifacts, the
// reserved top-level "artifacts" key is set to where each file is, replacing
// anything the server put there (contract §3.6); without, the payload is
// written unchanged.
func writePayload(path string, task taskstore.Task, artifactPaths map[string]string) error {
	payload := task.Payload
	if len(task.Artifacts) > 0 {
		payload = make(map[string]interface{}, len(task.Payload)+1)
		for k, v := range task.Payload {
			payload[k] = v
		}
		infos := make(map[string]artifactInfo, len(task.Artifacts))
		for _, a := range task.Artifacts {
			infos[a.ID] = artifactInfo{Path: artifactPaths[a.ID], Filename: a.Filename, SHA256: a.SHA256, Size: a.Size}
		}
		payload["artifacts"] = infos
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// scriptEnv is the environment a script gets on top of the agent's (contract
// §3.6). The first three are set for every script task.
func scriptEnv(task taskstore.Task, tempDir, artifactsDir string, artifactPaths map[string]string) []string {
	env := []string{
		"SENTINEL_TASK_ID=" + task.ID,
		"SENTINEL_TASK_DIR=" + tempDir,
		"SENTINEL_ARTIFACTS_DIR=" + artifactsDir,
	}
	for _, a := range task.Artifacts {
		env = append(env, "SENTINEL_ARTIFACT_"+strings.ToUpper(a.ID)+"="+artifactPaths[a.ID])
	}
	return env
}

// scriptRef says where a task's script comes from: a path in the
// command-scripts bucket, or a body sent inline with the task (contract §2).
// Exactly one of RemotePath and Body is set.
type scriptRef struct {
	RemotePath string
	Body       *string
	Filename   string
}

// resolveScript picks the script entry for this OS, falling back to "all".
// Within an entry a non-empty path wins over an inline body.
func (s *TaskExecutorService) resolveScript(task taskstore.Task) (scriptRef, error) {
	osKey := runtime.GOOS

	for _, key := range []string{osKey, "all"} {
		entry, ok := task.Scripts[key].(map[string]interface{})
		if !ok {
			continue
		}
		ref, found, err := resolveScriptEntry(entry)
		if err != nil {
			return scriptRef{}, fmt.Errorf("script for %s: %w", key, err)
		}
		if found {
			return ref, nil
		}
	}

	return scriptRef{}, fmt.Errorf("no script found for platform: %s", osKey)
}

// resolveScriptEntry reads one scripts[<key>] entry. found is false when the
// entry has neither a path nor a body.
func resolveScriptEntry(entry map[string]interface{}) (ref scriptRef, found bool, err error) {
	if path, ok := entry["path"].(string); ok && path != "" {
		// Path-based scripts keep their existing naming; the path comes from
		// our own bucket listing, not a free-form field.
		return scriptRef{RemotePath: path, Filename: filepath.Base(path)}, true, nil
	}

	body, ok := entry["body"].(string)
	if !ok {
		return scriptRef{}, false, nil
	}
	if body == "" {
		return scriptRef{}, false, fmt.Errorf("inline script body is empty")
	}
	if len(body) > maxScriptBytes {
		return scriptRef{}, false, fmt.Errorf("inline script is %d bytes, over the %d byte limit", len(body), maxScriptBytes)
	}

	filename := defaultScriptFilename()
	if raw, present := entry["filename"]; present {
		name, isString := raw.(string)
		if !isString {
			return scriptRef{}, false, fmt.Errorf("inline script filename is not a string")
		}
		filename = name
	}
	if err := validateScriptFilename(filename); err != nil {
		return scriptRef{}, false, err
	}

	return scriptRef{Body: &body, Filename: filename}, true, nil
}

// defaultScriptFilename names an inline script that came without a filename.
// The extension picks the interpreter in executeLocalScript.
func defaultScriptFilename() string {
	if runtime.GOOS == "windows" {
		return "install.ps1"
	}
	return "install.sh"
}

// validateScriptFilename applies the contract §1 filename rule.
func validateScriptFilename(name string) error {
	if err := artifact.ValidateFilename(name); err != nil {
		return fmt.Errorf("invalid inline script filename: %w", err)
	}
	return nil
}

// writeInlineScript writes an inline body into the task temp dir with the
// same 0700 mode that downloaded scripts get before they run.
func writeInlineScript(localPath, body string) error {
	// #nosec G306 - the script must be executable by its owner; the temp dir is 0700
	return os.WriteFile(localPath, []byte(body), 0700)
}

func (s *TaskExecutorService) downloadScript(ctx context.Context, remotePath, localPath string) error {
	// #nosec G304 - localPath is a controlled path from task store
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}

	// A script over the limit is rejected (supabase.ErrTooLarge) instead of
	// being truncated and then executed, as io.LimitReader used to do.
	c := supabase.FromConfig(s.cfg, supabase.WithHTTPClient(s.client))
	_, dlErr := c.Download(ctx, "command-scripts", remotePath, true, out, maxScriptBytes)
	closeErr := out.Close()
	if dlErr != nil {
		_ = os.Remove(localPath)
		return dlErr
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return fmt.Errorf("close downloaded script: %w", closeErr)
	}
	return nil
}

// maxScriptBytes is the largest command script the agent will download.
const maxScriptBytes = 10 << 20
