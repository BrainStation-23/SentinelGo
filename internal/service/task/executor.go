package task

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/updater"
)

// TaskExecutorService handles the execution of tasks assigned to the agent.
type TaskExecutorService struct {
	cfg          *config.Config
	pollingSvc   *TaskPollingService
	client       *http.Client
	runningTasks map[string]bool
}

// NewTaskExecutorService creates a new task execution service.
func NewTaskExecutorService(cfg *config.Config, pollingSvc *TaskPollingService) *TaskExecutorService {
	return &TaskExecutorService{
		cfg:          cfg,
		pollingSvc:   pollingSvc,
		client:       httpx.NewClient(2 * time.Minute),
		runningTasks: make(map[string]bool),
	}
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

// ExecutePendingTasks finds locally stored 'assigned' tasks and runs them.
func (s *TaskExecutorService) ExecutePendingTasks(ctx context.Context) {
	tasks, err := s.pollingSvc.GetLocalTasks()
	fmt.Printf("Executor: Found %d local tasks to execute\n", len(tasks))
	if err != nil {
		log.Printf("Executor: Failed to get local tasks: %v", err)
		return
	}

	for _, task := range tasks {
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
		} else {
			log.Printf("Executor: Task %s completed successfully", task.ID)
			statusNote := note
			if statusNote == "" {
				statusNote = "Executed successfully"
			}
			if err := s.pollingSvc.ReportTaskStatus(ctx, task.ID, "success", statusNote); err != nil {
				log.Printf("Executor: Failed to report task status: %v", err)
			}
		}
	}
}

func (s *TaskExecutorService) runTask(ctx context.Context, task taskstore.Task) (string, error) {
	if task.Slug == "agent-update" || task.Slug == "update-agent" {
		return s.executeAgentUpdate(ctx, task)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	scriptPath, scriptName, err := s.resolveScript(task)
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

	localScriptPath := filepath.Join(tempDir, scriptName)
	if err := s.downloadScript(timeoutCtx, scriptPath, localScriptPath); err != nil {
		return "", fmt.Errorf("download script: %w", err)
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
		output, err := s.executeLocalScript(timeoutCtx, localScriptPath, payloadPath)
		resultChan <- struct {
			output string
			err    error
		}{output, err}
	}()

	select {
	case <-timeoutCtx.Done():
		timeoutNote := fmt.Sprintf("Task execution timed out after 10 minutes. Task ID: %s, Slug: %s. The task was forcefully stopped.", task.ID, task.Slug)
		log.Printf("Executor: %s", timeoutNote)
		return timeoutNote, fmt.Errorf("task execution timeout")
	case result := <-resultChan:
		return result.output, result.err
	}
}

func (s *TaskExecutorService) resolveScript(task taskstore.Task) (string, string, error) {
	osKey := runtime.GOOS

	if scriptObj, ok := task.Scripts[osKey].(map[string]interface{}); ok {
		if path, ok := scriptObj["path"].(string); ok {
			return path, filepath.Base(path), nil
		}
	}

	if scriptObj, ok := task.Scripts["all"].(map[string]interface{}); ok {
		if path, ok := scriptObj["path"].(string); ok {
			return path, filepath.Base(path), nil
		}
	}

	return "", "", fmt.Errorf("no script found for platform: %s", osKey)
}

func (s *TaskExecutorService) downloadScript(ctx context.Context, remotePath, localPath string) error {
	url := fmt.Sprintf("%s/storage/v1/object/authenticated/command-scripts/%s", s.cfg.SupabaseURL, remotePath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("apikey", s.cfg.SupabaseKey)
	req.Header.Set("Authorization", "Bearer "+s.cfg.AccessToken)

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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
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
	_, err = io.Copy(out, io.LimitReader(resp.Body, maxScriptBytes))
	return err
}

// executeAgentUpdate handles the agent-update task by directly invoking the updater.
func (s *TaskExecutorService) executeAgentUpdate(ctx context.Context, task taskstore.Task) (string, error) {
	log.Printf("Executor: Executing agent-update task %s", task.ID)

	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		log.Printf("Executor: Agent-update requires root privileges")
		return "", fmt.Errorf("agent-update requires root privileges. Please restart the agent with sudo")
	}

	if !updater.CheckInternetConnectivity() {
		log.Printf("Executor: Warning - TCP connectivity check failed, attempting update anyway")
	}

	if !updater.CheckInternetWithHTTP() {
		log.Printf("Executor: Warning - HTTP connectivity check failed, attempting update anyway")
	}

	currentVersion := s.cfg.CurrentVersion
	if currentVersion == "" {
		currentVersion = config.Version
	}

	sanitizedCurrentVersion := sanitize.ForLog(currentVersion)
	log.Printf("Executor: Current version: %s, checking for updates...", sanitizedCurrentVersion)

	if err := updater.CheckAndApplyWithRetry(ctx, s.cfg, ""); err != nil {
		log.Printf("Executor: Agent-update failed: %v", err)
		return fmt.Sprintf("Update failed: %v (Current version: %s)", err, sanitizedCurrentVersion), err
	}

	newVersion := s.cfg.CurrentVersion
	sanitizedNewVersion := sanitize.ForLog(newVersion)
	log.Printf("Executor: Agent-update successful, updated from %s to %s", sanitizedCurrentVersion, sanitizedNewVersion)

	return fmt.Sprintf("Successfully updated from %s to %s. Agent is restarting.", sanitizedCurrentVersion, sanitizedNewVersion), nil
}
