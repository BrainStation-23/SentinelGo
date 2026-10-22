package task

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// executeLocalScript runs the task script on macOS. env is added to the
// agent's environment.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string, env []string) (string, error) {
	// #nosec G302 - Executable scripts need 0755 permissions
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return "", fmt.Errorf("chmod failed: %w", err)
	}

	args, err := scriptArgv(scriptPath, payloadPath)
	if err != nil {
		return "", err
	}
	// #nosec G204 - scriptPath is a controlled path from task store
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = 30 * time.Second

	return runBounded(cmd)
}
