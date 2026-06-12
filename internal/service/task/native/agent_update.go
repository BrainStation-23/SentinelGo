package native

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/updater"
)

type agentUpdateHandler struct{}

func init() { Register(&agentUpdateHandler{}) }

func (h *agentUpdateHandler) Slugs() []string {
	return []string{"agent-update"}
}

func (h *agentUpdateHandler) PostRun() []string {
	return []string{"sync-inventory"}
}

func (h *agentUpdateHandler) Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error) {
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

	currentVersion := cfg.CurrentVersion
	if currentVersion == "" {
		currentVersion = config.Version
	}

	sanitizedCurrentVersion := sanitize.ForLog(currentVersion)
	log.Printf("Executor: Current version: %s, checking for updates...", sanitizedCurrentVersion)

	// Write the restart context before calling the updater. If CheckAndApply
	// finds an update it calls os.Exit(), so this file is the only way the
	// restarted binary knows which task to mark as success.
	ctxPath := restartctx.PathFor(cfg.Path)
	if err := restartctx.Write(ctxPath, restartctx.Context{
		TaskID:      task.ID,
		Reason:      "agent-update",
		FromVersion: currentVersion,
		InitiatedAt: time.Now().UTC(),
	}); err != nil {
		log.Printf("Executor: Warning - failed to write restart context: %v", err)
	}

	if err := updater.CheckAndApplyWithRetry(ctx, cfg, ""); err != nil {
		// Update failed or was not needed; remove the context so the next
		// startup does not incorrectly mark this task as success.
		_, _ = restartctx.ReadAndClear(ctxPath)
		log.Printf("Executor: Agent-update failed: %v", err)
		return fmt.Sprintf("Update failed: %v (Current version: %s)", err, sanitizedCurrentVersion), err
	}

	// Reached here only when no update was available (already up to date).
	// CheckAndApplyWithRetry calls os.Exit() on a successful update, so this
	// line is never reached in the update case.
	_, _ = restartctx.ReadAndClear(ctxPath)
	log.Printf("Executor: Agent is already up to date (version %s)", sanitizedCurrentVersion)
	return fmt.Sprintf("Already up to date (version %s).", sanitizedCurrentVersion), nil
}
