package shared

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"sentinelgo/internal/binpath"
	"sentinelgo/internal/sanitize"
)

func ReadFileContent(path string) (string, error) {
	// #nosec G304 - path is a controlled internal parameter
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Strip NUL bytes so downstream payloads stay valid for Postgres text/jsonb.
	return sanitize.StripNUL(string(data)), nil
}

func ReadFileBytes(path string) ([]byte, error) {
	// #nosec G304 - path is a controlled internal parameter
	return os.ReadFile(path)
}

// RunPowerShell runs script via a non-interactive, profile-less PowerShell
// invocation. This exact flag combination ("-NoProfile", "-Command") is
// shared by every Windows collector, so it's centralized here rather than
// repeated at each call site.
func RunPowerShell(script string) (string, error) {
	return RunCommand("powershell", "-NoProfile", "-Command", script)
}

// LookupBinary returns the fixed install path of a well-known system tool
// (binpath.Lookup), or an error when it isn't installed there. The tool is
// then skipped rather than looked up in PATH, where a writable directory
// could substitute it while the agent runs as root/SYSTEM. A name binpath
// doesn't know is returned unchanged.
func LookupBinary(name string) (string, error) {
	path, ok := binpath.Lookup(name)
	if !ok {
		return "", fmt.Errorf("%s: not installed at a known system path", name)
	}
	return path, nil
}

// RunCommand runs name with args and returns stdout. name is resolved with
// LookupBinary, so a well-known tool runs only from its fixed install path.
func RunCommand(name string, args ...string) (string, error) {
	bin, err := LookupBinary(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, bin, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// Strip NUL bytes so downstream payloads stay valid for Postgres text/jsonb.
	return sanitize.StripNUL(string(output)), nil
}

// RunCommandOutput runs name with args and returns combined output plus exit code.
// Unlike RunCommand, a non-zero exit code is not treated as an error — only execution
// failures (command not found, timeout) return a non-nil error. Exit code -1 is
// returned when the process could not be started or timed out.
// This is needed for tools like yum check-update that signal "updates available"
// via exit code 100 rather than exit 0. name is resolved like RunCommand's.
func RunCommandOutput(name string, args ...string) (output string, exitCode int, err error) {
	bin, err := LookupBinary(name)
	if err != nil {
		return "", -1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, bin, args...)
	out, runErr := cmd.CombinedOutput()
	// Strip NUL bytes so downstream payloads stay valid for Postgres text/jsonb.
	output = sanitize.StripNUL(string(out))
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return output, exitErr.ExitCode(), nil
		}
		return output, -1, runErr
	}
	return output, 0, nil
}
