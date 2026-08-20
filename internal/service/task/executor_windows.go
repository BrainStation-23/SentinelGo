package task

import (
	"context"
	"os/exec"
	"path/filepath"
	"time"
)

// executeLocalScript runs the task script on Windows using PowerShell or cmd.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string) (string, error) {
	var cmd *exec.Cmd

	if filepath.Ext(scriptPath) == ".ps1" {
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-PayloadPath", payloadPath)
	} else {
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, "cmd", "/C", scriptPath, payloadPath)
	}

	cmd.WaitDelay = 30 * time.Second

	return runCommandBounded(cmd)
}
