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
)

// executeLocalScript runs the task script on Linux, optionally using sudo for
// scripts that contain privileged commands.
func (s *TaskExecutorService) executeLocalScript(ctx context.Context, scriptPath, payloadPath string) (string, error) {
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

	ext := filepath.Ext(scriptPath)

	var cmd *exec.Cmd

	if needsSudo {
		var args []string
		args = append(args, "sudo", "-S")
		switch ext {
		case ".sh":
			args = append(args, "bash", scriptPath, payloadPath)
		case ".py":
			args = append(args, "python3", scriptPath, payloadPath)
		default:
			args = append(args, scriptPath, payloadPath)
		}
		// #nosec G204 - args are validated and controlled
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
		// Do not set cmd.Stdin: when running as a system service os.Stdin is
		// /dev/null, causing sudo -S to hang. If the agent lacks root, the
		// task will fail with a clear error.
		cmd.Env = append(os.Environ(), "SUDO_PROMPT=[sudo] password for %u: ")
	} else {
		switch ext {
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
	}

	// Give the subprocess 30 s to exit cleanly after context cancellation
	// before escalating to SIGKILL, so processes that ignore SIGTERM don't
	// block the goroutine indefinitely.
	cmd.WaitDelay = 30 * time.Second

	return runCommandBounded(cmd)
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
