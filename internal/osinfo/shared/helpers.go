package shared

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

func ReadFileContent(path string) (string, error) {
	// #nosec G304 - path is a controlled internal parameter
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ReadFileBytes(path string) ([]byte, error) {
	// #nosec G304 - path is a controlled internal parameter
	return os.ReadFile(path)
}

func RunCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// RunCommandOutput runs name with args and returns combined output plus exit code.
// Unlike RunCommand, a non-zero exit code is not treated as an error — only execution
// failures (command not found, timeout) return a non-nil error. Exit code -1 is
// returned when the process could not be started or timed out.
// This is needed for tools like yum check-update that signal "updates available"
// via exit code 100 rather than exit 0.
func RunCommandOutput(name string, args ...string) (output string, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
	out, runErr := cmd.CombinedOutput()
	output = string(out)
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return output, exitErr.ExitCode(), nil
		}
		return output, -1, runErr
	}
	return output, 0, nil
}
