package procinfo

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ProcessInfo contains information about a running SentinelGo process
type ProcessInfo struct {
	PID     int
	Version string
	CmdLine string
	Status  string
}

// GetCheckpointPath returns the path for checkpoint storage
func GetCheckpointPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\SentinelGo\.sentinelgo\audit_checkpoint.json`
	case "linux", "darwin":
		return "/opt/sentinelgo/.sentinelgo/audit_checkpoint.json"
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/sentinelgo_audit_checkpoint.json"
		}
		return fmt.Sprintf("%s/.sentinelgo/audit_checkpoint.json", home)
	}
}

// ExtractVersionFromCmd tries to extract version from command line arguments
func ExtractVersionFromCmd(cmdLine string) string {
	// Look for -version flag in command line
	if strings.Contains(cmdLine, "-version=") {
		parts := strings.Split(cmdLine, "-version=")
		if len(parts) > 1 {
			version := strings.Split(parts[1], " ")[0]
			return strings.Trim(version, `"`)
		}
	}

	// Look for version flag as separate argument
	if strings.Contains(cmdLine, "-version") || strings.Contains(cmdLine, "--version") {
		// Try to find version after the flag
		parts := strings.Fields(cmdLine)
		for i, part := range parts {
			if (part == "-version" || part == "--version") && i+1 < len(parts) {
				return strings.Trim(parts[i+1], `"`)
			}
		}
	}

	return "unknown"
}

// ParseProcessOutput parses the output of process listing commands
func ParseProcessOutput(output string) []ProcessInfo {
	var processes []ProcessInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var info ProcessInfo

		switch runtime.GOOS {
		case "windows":
			if strings.Contains(line, "sentinelgo.exe") {
				fields := strings.Split(line, ",")
				if len(fields) >= 5 {
					pid, _ := strconv.Atoi(strings.Trim(fields[1], `"`))
					info.PID = pid
					info.CmdLine = strings.Trim(fields[8], `"`)
					info.Status = "Running"

					info.Version = ExtractVersionFromCmd(info.CmdLine)
					if info.Version == "unknown" {
						info.Version = GetBinaryVersion(info.CmdLine)
					}
				}
			}
		case "linux", "darwin":
			if strings.Contains(line, "sentinelgo") && !strings.Contains(line, "grep") && !strings.Contains(line, "systemctl") && !strings.Contains(line, "journalctl") && !strings.Contains(line, "editor") {
				fields := strings.Fields(line)
				if len(fields) >= 11 {
					pid, _ := strconv.Atoi(fields[1])
					info.PID = pid
					info.CmdLine = strings.Join(fields[10:], " ")
					info.Status = "Running"

					info.Version = ExtractVersionFromCmd(info.CmdLine)
					if info.Version == "unknown" {
						info.Version = GetBinaryVersion(info.CmdLine)
					}
				}
			}
		}

		if info.PID > 0 {
			processes = append(processes, info)
		}
	}

	return processes
}

// GetBinaryVersion tries to get version from the binary executable
func GetBinaryVersion(cmdLine string) string {
	var binaryPath string
	parts := strings.Fields(cmdLine)

	if len(parts) > 0 {
		binaryPath = parts[0]
		if !strings.Contains(binaryPath, "/") && runtime.GOOS != "windows" {
			if path, err := exec.LookPath(binaryPath); err == nil {
				binaryPath = path
			}
		}
	}

	if binaryPath != "" {
		// #nosec G204 - binaryPath is a controlled path from self-update process
		cmd := exec.Command(binaryPath, "-version")
		output, err := cmd.Output()
		if err == nil {
			outputStr := string(output)
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "version:") || strings.Contains(line, "version") {
					lineParts := strings.Fields(line)
					for i, part := range lineParts {
						if strings.Contains(part, "version") && i+1 < len(lineParts) {
							return strings.Trim(lineParts[i+1], ",")
						}
					}
				}
			}
		}
	}

	return "unknown"
}

// FindProcesses finds all running SentinelGo processes
func FindProcesses() ([]ProcessInfo, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("tasklist", "/fi", "imagename eq sentinelgo.exe", "/fo", "csv", "/v")
	case "linux", "darwin":
		cmd = exec.Command("ps", "aux")
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	// Add timeout to prevent goroutine leaks in tests
	type result struct {
		output []byte
		err    error
	}

	resultChan := make(chan result, 1)
	go func() {
		output, err := cmd.Output()
		resultChan <- result{output, err}
	}()

	select {
	case res := <-resultChan:
		if res.err != nil {
			return nil, res.err
		}
		return ParseProcessOutput(string(res.output)), nil
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil, fmt.Errorf("process listing timed out after 5 seconds")
	}
}
