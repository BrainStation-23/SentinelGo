package updater

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/config"
)

// findOldProcesses finds all running SentinelGo processes except the current one.
func findOldProcesses() ([]ProcessInfo, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tasklist", "/fi", "imagename eq sentinelgo.exe", "/fo", "csv", "/v")
	case "linux", "darwin":
		cmd = exec.Command("ps", "aux")
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseProcessOutput(string(output)), nil
}

func parseProcessOutput(output string) []ProcessInfo {
	var processes []ProcessInfo
	currentPID := os.Getpid()
	currentVersion := getCurrentVersion()

	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var info ProcessInfo

		switch runtime.GOOS {
		case "windows":
			if !strings.Contains(line, "sentinelgo.exe") {
				continue
			}
			fields := strings.Split(line, ",")
			if len(fields) < 5 {
				continue
			}
			pid, _ := strconv.Atoi(strings.Trim(fields[1], `"`))
			if pid == currentPID {
				continue
			}
			info.PID = pid
			if len(fields) > 8 {
				info.CmdLine = strings.Trim(fields[8], `"`)
			}
			info.Version = getProcessVersion(info.CmdLine, pid)
			// Only kill if version is positively known to be different.
			// Skipping "unknown" prevents killing newly started processes.
			if info.Version != "unknown" && info.Version != currentVersion {
				processes = append(processes, info)
			}

		case "linux", "darwin":
			if !strings.Contains(line, "sentinelgo") ||
				strings.Contains(line, "grep") ||
				strings.Contains(line, "systemctl") ||
				strings.Contains(line, "journalctl") ||
				strings.Contains(line, "editor") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, _ := strconv.Atoi(fields[1])
			if pid == currentPID {
				continue
			}
			info.PID = pid
			if len(fields) > 10 {
				info.CmdLine = strings.Join(fields[10:], " ")
			}
			info.Version = getProcessVersion(info.CmdLine, pid)
			if info.Version != "unknown" && info.Version != currentVersion {
				processes = append(processes, info)
			}
		}
	}

	return processes
}

func getProcessVersion(cmdLine string, pid int) string {
	if version := extractVersionFromCmd(cmdLine); version != "unknown" {
		return version
	}
	if version := getBinaryVersion(cmdLine); version != "unknown" {
		return version
	}
	if version := extractVersionFromPath(cmdLine); version != "unknown" {
		return version
	}
	return "unknown"
}

func extractVersionFromCmd(cmdLine string) string {
	if strings.Contains(cmdLine, "-version=") {
		parts := strings.Split(cmdLine, "-version=")
		if len(parts) > 1 {
			return strings.Trim(strings.Split(parts[1], " ")[0], `"`)
		}
	}

	parts := strings.Fields(cmdLine)
	for i, part := range parts {
		if (part == "-version" || part == "--version") && i+1 < len(parts) {
			return strings.Trim(parts[i+1], `"`)
		}
	}

	return "unknown"
}

func getBinaryVersion(cmdLine string) string {
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return "unknown"
	}

	binaryPath := parts[0]
	if !strings.Contains(binaryPath, "/") && runtime.GOOS != "windows" {
		if path, err := exec.LookPath(binaryPath); err == nil {
			binaryPath = path
		}
	}

	if binaryPath == "" {
		return "unknown"
	}

	// #nosec G204 - binaryPath is a controlled path from self-update process
	output, err := exec.Command(binaryPath, "-version").Output()
	if err != nil {
		return "unknown"
	}

	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, "version") {
			continue
		}
		fields := strings.Fields(line)
		for i, part := range fields {
			if strings.Contains(part, "version") && i+1 < len(fields) {
				return strings.Trim(fields[i+1], ",")
			}
		}
	}

	return "unknown"
}

func getCurrentVersion() string {
	cfg, err := config.Load("")
	if err == nil && cfg.CurrentVersion != "" {
		return cfg.CurrentVersion
	}
	return config.Version
}

func extractVersionFromPath(path string) string {
	for _, part := range strings.Split(path, "-") {
		if strings.HasPrefix(part, "v") {
			return strings.Trim(part, `"`)
		}
	}
	return "unknown"
}

// stopOldProcesses sends SIGTERM to old processes, waits, then force-kills any remaining.
func stopOldProcesses() error {
	processes, err := findOldProcesses()
	if err != nil {
		return err
	}

	if len(processes) == 0 {
		fmt.Println("No old SentinelGo processes found")
		return nil
	}

	fmt.Printf("Found %d old SentinelGo process(es) to stop:\n", len(processes))
	for _, proc := range processes {
		fmt.Printf("  PID: %d, Version: %s\n", proc.PID, proc.Version)
	}

	fmt.Println("Stopping old processes...")
	for _, proc := range processes {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			// #nosec G204 - taskkill is a system command with controlled arguments
			cmd = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID))
		case "linux", "darwin":
			// #nosec G204 - kill is a system command with controlled arguments
			cmd = exec.Command("kill", "-TERM", strconv.Itoa(proc.PID))
		}

		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to stop PID %d: %v\n", proc.PID, err)
		} else {
			fmt.Printf("Stopped PID %d\n", proc.PID)
		}
	}

	time.Sleep(3 * time.Second)

	remaining, _ := findOldProcesses()
	if len(remaining) > 0 {
		fmt.Printf("Force killing %d remaining process(es)...\n", len(remaining))
		forceKillProcesses(remaining)
		time.Sleep(2 * time.Second)
	}

	return nil
}
