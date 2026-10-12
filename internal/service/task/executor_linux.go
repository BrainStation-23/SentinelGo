package task

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
)

// executeLocalScript runs the task script on Linux, optionally using sudo for
// scripts that contain privileged commands. env is added to the agent's
// environment, and is passed through sudo explicitly.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string, env []string) (string, error) {
	needsSudo := false

	// #nosec G304 - scriptPath is a controlled path from task store
	content, err := os.ReadFile(scriptPath)
	if err == nil {
		if containsPrivilegedCommands(string(content)) && os.Getuid() != 0 {
			needsSudo = true
			log.Printf("Executor: Task requires root privileges, using sudo")
		}
	}

	// #nosec G302 - Executable scripts need 0755 permissions
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return "", fmt.Errorf("chmod failed: %w", err)
	}

	cmd := linuxScriptCommand(ctx, scriptPath, payloadPath, env, needsSudo)

	// Give the subprocess 30 s to exit cleanly after context cancellation
	// before escalating to SIGKILL, so processes that ignore SIGTERM don't
	// block the goroutine indefinitely.
	cmd.WaitDelay = 30 * time.Second

	return runBounded(cmd)
}

// linuxScriptCommand builds the command for a script: the interpreter its
// extension picks, under sudo when needsSudo is set.
func linuxScriptCommand(ctx context.Context, scriptPath, payloadPath string, env []string, needsSudo bool) *exec.Cmd {
	var args []string
	switch filepath.Ext(scriptPath) {
	case ".sh":
		args = []string{binpath.Resolve("bash"), scriptPath, payloadPath}
	case ".py":
		args = []string{binpath.Resolve("python3"), scriptPath, payloadPath}
	default:
		args = []string{scriptPath, payloadPath}
	}

	if !needsSudo {
		// #nosec G204 - scriptPath is a controlled path from task store
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), env...)
		return cmd
	}

	// sudo resets the environment by default (env_reset), so the task's
	// variables are handed to the script through env(1) inside sudo.
	sudoArgs := []string{"-S"}
	if len(env) > 0 {
		sudoArgs = append(sudoArgs, binpath.Resolve("env"))
		sudoArgs = append(sudoArgs, env...)
	}
	sudoArgs = append(sudoArgs, args...)
	// #nosec G204 - args are validated and controlled
	cmd := exec.CommandContext(ctx, binpath.Resolve("sudo"), sudoArgs...)
	// Do not set cmd.Stdin: when running as a system service os.Stdin is
	// /dev/null, causing sudo -S to hang. If the agent lacks root, the
	// task will fail with a clear error.
	cmd.Env = append(os.Environ(), "SUDO_PROMPT=[sudo] password for %u: ")
	return cmd
}

// containsPrivilegedCommands reports whether the script contains commands that
// typically require root privileges.
func containsPrivilegedCommands(scriptContent string) bool {
	privilegedCommands := []string{
		"modprobe", "insmod", "rmmod",
		"systemctl", "service",
		"/etc/", "/sys/", "/proc/",
		"mount", "umount",
		"chown", "chmod 777", "chmod 755",
		"iptables", "sysctl",
	}
	for _, cmd := range privilegedCommands {
		if strings.Contains(scriptContent, cmd) {
			return true
		}
	}
	return false
}
