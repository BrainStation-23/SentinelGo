//go:build linux

package prompt

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// errNoDialogBackend is returned when neither zenity nor kdialog is
// installed — see LinuxPrompter.Available.
var errNoDialogBackend = errors.New("prompt: neither zenity nor kdialog is available")

// dialogTimeout bounds how long a dialog subprocess may block waiting for
// user input. A prompt nobody answers must not hang the session helper
// forever — matching Constraints.MaxRuntime's existing "bounded, not
// indefinite" philosophy elsewhere in this package tree.
const dialogTimeout = 5 * time.Minute

func runCommandReal(name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()

	// #nosec G204 - name/args are fixed dialog-tool invocations built from
	// caller-supplied title/message text, not an externally controlled
	// command name.
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return string(out), 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode(), nil
	}
	return "", -1, err
}
