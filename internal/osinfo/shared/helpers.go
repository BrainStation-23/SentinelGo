package shared

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

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

func RunCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
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
// via exit code 100 rather than exit 0.
func RunCommandOutput(name string, args ...string) (output string, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
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

// commandWaitDelay bounds how long Wait blocks after the context is cancelled.
//
// exec.CommandContext kills the direct child on cancellation, but Wait still
// blocks until the child's stdout/stderr pipes close. A child that spawned
// grandchildren (powershell launching a helper, smartctl on a stuck device)
// leaves those pipes open, so without WaitDelay a "cancelled" command can hang
// the caller indefinitely — the process is dead but the goroutine is not. With
// it, the pipes are force-closed and Wait returns.
const commandWaitDelay = 5 * time.Second

// RunCommandContext runs name with args under the caller's context and returns
// stdout.
//
// This is the context-aware sibling of RunCommand. New collectors must use it:
// telemetry collection runs under a deadline, and a subprocess that ignores
// cancellation outlives the cycle that started it. RunCommand is unchanged and
// remains valid for existing callers.
//
// Cancellation semantics: the child is killed when ctx is done, and Wait is
// bounded by commandWaitDelay so a grandchild holding the pipes open cannot
// stall the caller.
func RunCommandContext(ctx context.Context, name string, args ...string) (string, error) {
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = commandWaitDelay

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// Strip NUL bytes so downstream payloads stay valid for Postgres text/jsonb.
	return sanitize.StripNUL(string(output)), nil
}

// RunCommandOutputContext runs name with args under the caller's context and
// returns combined output plus the exit code.
//
// Like RunCommandOutput, a non-zero exit is not an error — only execution
// failures are. This is required for tools that signal state through exit codes
// (smartctl uses exit-code bit flags for drive health, yum check-update uses
// 100 for "updates available"), where treating a non-zero exit as failure would
// discard exactly the output that matters.
func RunCommandOutputContext(ctx context.Context, name string, args ...string) (output string, exitCode int, err error) {
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = commandWaitDelay

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
