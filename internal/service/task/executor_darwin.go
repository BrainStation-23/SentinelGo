package task

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// executeLocalScript runs the task script on macOS.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string) (string, error) {
	// #nosec G302 - Executable scripts need 0755 permissions
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return "", fmt.Errorf("chmod failed: %w", err)
	}

	var cmd *exec.Cmd

	switch filepath.Ext(scriptPath) {
	case ".sh":
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, "bash", scriptPath, payloadPath)
	case ".py":
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, "python3", scriptPath, payloadPath)
	default:
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, scriptPath, payloadPath)
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}
