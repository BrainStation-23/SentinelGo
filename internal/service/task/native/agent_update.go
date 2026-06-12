package native

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
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

	if err := updater.CheckAndApplyWithRetry(ctx, cfg, ""); err != nil {
		log.Printf("Executor: Agent-update failed: %v", err)
		return fmt.Sprintf("Update failed: %v (Current version: %s)", err, sanitizedCurrentVersion), err
	}

	newVersion := cfg.CurrentVersion
	sanitizedNewVersion := sanitize.ForLog(newVersion)
	log.Printf("Executor: Agent-update successful, updated from %s to %s", sanitizedCurrentVersion, sanitizedNewVersion)

	return fmt.Sprintf("Successfully updated from %s to %s. Agent is restarting.", sanitizedCurrentVersion, sanitizedNewVersion), nil
}
