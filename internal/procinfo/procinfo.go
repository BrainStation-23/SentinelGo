package procinfo

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
)

// versionFlag is the short-form version flag SentinelGo binaries accept,
// checked both when parsing another process's command line and when probing
// a binary directly.
const versionFlag = "-version"

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
	if strings.Contains(cmdLine, versionFlag) || strings.Contains(cmdLine, "--version") {
		// Try to find version after the flag
		parts := strings.Fields(cmdLine)
		for i, part := range parts {
			if (part == versionFlag || part == "--version") && i+1 < len(parts) {
				return strings.Trim(parts[i+1], `"`)
			}
		}
	}

	return "unknown"
}

// resolveVersion tries ExtractVersionFromCmd first (fast, no subprocess),
// falling back to actually invoking the binary with -version.
func resolveVersion(cmdLine string) string {
	version := ExtractVersionFromCmd(cmdLine)
	if version == "unknown" {
		version = GetBinaryVersion(cmdLine)
	}
	return version
}

// tasklistCmdLineField is the index of the command-line column read from a
// `tasklist /fo csv /v` row, so a row needs at least tasklistCmdLineField+1 fields.
const tasklistCmdLineField = 8

// parseWindowsProcessLine parses one line of `tasklist /fo csv /v` output,
// returning a zero-value ProcessInfo (PID 0) when the line isn't a
// sentinelgo.exe entry or doesn't have enough CSV fields.
func parseWindowsProcessLine(line string) ProcessInfo {
	var info ProcessInfo
	if !strings.Contains(line, "sentinelgo.exe") {
		return info
	}
	fields := strings.Split(line, ",")
	if len(fields) <= tasklistCmdLineField {
		return info
	}
	pid, _ := strconv.Atoi(strings.Trim(fields[1], `"`))
	info.PID = pid
	info.CmdLine = strings.Trim(fields[tasklistCmdLineField], `"`)
	info.Status = "Running"
	info.Version = resolveVersion(info.CmdLine)
	return info
}

// unixProcessLineExclusions filters out `ps aux` lines that merely mention
// "sentinelgo" incidentally (the grep command itself, or a service manager
// / log viewer / editor showing it) rather than being the process itself.
var unixProcessLineExclusions = []string{"grep", "systemctl", "journalctl", "editor"}

// parseUnixProcessLine parses one line of `ps aux` output, returning a
// zero-value ProcessInfo (PID 0) when the line isn't a real sentinelgo
// process entry or doesn't have enough whitespace-separated fields.
func parseUnixProcessLine(line string) ProcessInfo {
	var info ProcessInfo
	if !strings.Contains(line, "sentinelgo") {
		return info
	}
	for _, excl := range unixProcessLineExclusions {
		if strings.Contains(line, excl) {
			return info
		}
	}
	fields := strings.Fields(line)
	if len(fields) < 11 {
		return info
	}
	pid, _ := strconv.Atoi(fields[1])
	info.PID = pid
	info.CmdLine = strings.Join(fields[10:], " ")
	info.Status = "Running"
	info.Version = resolveVersion(info.CmdLine)
	return info
}

// ParseProcessOutput parses the output of process listing commands
func ParseProcessOutput(output string) []ProcessInfo {
	var processes []ProcessInfo

	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var info ProcessInfo
		switch runtime.GOOS {
		case "windows":
			info = parseWindowsProcessLine(line)
		case "linux", "darwin":
			info = parseUnixProcessLine(line)
		}

		if info.PID > 0 {
			processes = append(processes, info)
		}
	}

	return processes
}

// resolveBinaryPath extracts the executable from cmdLine's first field,
// resolving it against PATH when it's a bare name (non-Windows only, since
// Windows process command lines are already absolute paths).
func resolveBinaryPath(cmdLine string) string {
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return ""
	}
	binaryPath := parts[0]
	if !strings.Contains(binaryPath, "/") && runtime.GOOS != "windows" {
		if path, err := exec.LookPath(binaryPath); err == nil {
			binaryPath = path
		}
	}
	return binaryPath
}

// extractVersionFromOutput scans `<binary> -version` output for the first
// "...version <value>" token pair and returns <value>, or "" if none found.
func extractVersionFromOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "version") {
			continue
		}
		lineParts := strings.Fields(line)
		for i, part := range lineParts {
			if strings.Contains(part, "version") && i+1 < len(lineParts) {
				return strings.Trim(lineParts[i+1], ",")
			}
		}
	}
	return ""
}

// GetBinaryVersion tries to get version from the binary executable
func GetBinaryVersion(cmdLine string) string {
	binaryPath := resolveBinaryPath(cmdLine)
	if binaryPath == "" {
		return "unknown"
	}

	// #nosec G204 - binaryPath is a controlled path from self-update process
	output, err := exec.Command(binaryPath, versionFlag).Output()
	if err != nil {
		return "unknown"
	}

	if version := extractVersionFromOutput(string(output)); version != "" {
		return version
	}
	return "unknown"
}

// FindProcesses finds all running SentinelGo processes
func FindProcesses() ([]ProcessInfo, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
		cmd = exec.Command(binpath.Resolve("tasklist"), "/fi", "imagename eq sentinelgo.exe", "/fo", "csv", "/v")
	case "linux", "darwin":
		// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
		cmd = exec.Command(binpath.Resolve("ps"), "aux")
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
