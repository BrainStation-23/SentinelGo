package task

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sentinelgo/internal/binpath"
)

// executeLocalScript runs the task script on Windows using PowerShell or cmd.
// env is added to the agent's environment.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string, env []string) (string, error) {
	var cmd *exec.Cmd

	if filepath.Ext(scriptPath) == ".ps1" {
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, binpath.Resolve("powershell"), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-PayloadPath", payloadPath)
	} else {
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd = exec.CommandContext(ctx, binpath.Resolve("cmd"), "/C", scriptPath, payloadPath)
	}

	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = 30 * time.Second

	return runBounded(cmd)
}
