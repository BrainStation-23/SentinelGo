//go:build darwin

package prompt

import (
	"context"
	"os/exec"
	"time"
)

// dialogTimeout bounds how long a dialog subprocess may block waiting for
// user input — see prompt_linux.go's identical constant/reasoning.
const dialogTimeout = 5 * time.Minute

// runOsascriptReal runs `osascript -e script` and returns its stdout, exit
// code, and (on a genuine execution failure, not a normal non-zero exit)
// an error whose message includes stderr — DarwinPrompter checks that
// message for AppleScript's "-128" user-cancelled signature.
func runOsascriptReal(script string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	out, err := cmd.Output()
	if err == nil {
		return string(out), 0, nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode(), &osascriptError{stderr: string(exitErr.Stderr)}
	}
	return "", -1, err
}

type osascriptError struct{ stderr string }

func (e *osascriptError) Error() string { return e.stderr }
