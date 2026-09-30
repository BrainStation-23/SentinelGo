package native

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task/restartctx"
	"sentinelgo/internal/taskstore"
)

// rebootFn is the OS-reboot entry point. Replaced in tests.
var rebootFn = triggerReboot

type rebootDeviceHandler struct{}

func init() { Register(&rebootDeviceHandler{}) }

func (h *rebootDeviceHandler) Slugs() []string {
	return []string{"device-reboot"}
}

func (h *rebootDeviceHandler) Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error) {
	log.Printf("Executor: Executing reboot-device task %s", task.ID)

	if runtime.GOOS == "linux" && os.Getuid() != 0 {
		return "", fmt.Errorf("reboot-device requires root privileges. Please restart the agent with sudo")
	}

	ctxPath := restartctx.PathFor(cfg.Path)
	if err := restartctx.Write(ctxPath, restartctx.Context{
		TaskID:      task.ID,
		Reason:      "device-reboot",
		InitiatedAt: time.Now().UTC(),
	}); err != nil {
		log.Printf("Executor: Warning - failed to write restart context: %v", err)
	}

	if err := rebootFn(); err != nil {
		_, _ = restartctx.ReadAndClear(ctxPath)
		return "", fmt.Errorf("reboot failed: %w", err)
	}

	log.Printf("Executor: Device reboot initiated for task %s", task.ID)
	return "Device reboot initiated.", nil
}
