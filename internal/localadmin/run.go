package localadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strings"

	"sentinelgo/internal/binpath"
)

// Runner runs a tool by its binpath name with args and extra environment
// variables, and returns its standard output. A non-zero exit is an error
// that carries the tool's standard error.
type Runner func(ctx context.Context, tool string, args []string, env []string) (string, error)

// ExitError is a tool that ran and failed.
type ExitError struct {
	Tool   string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("%s exited with %d", e.Tool, e.Code)
	}
	return fmt.Sprintf("%s exited with %d: %s", e.Tool, e.Code, msg)
}

// Exec is the real Runner: the tool runs only from its fixed system path
// (never a PATH lookup, since the agent runs as root/SYSTEM), with no
// console window on Windows.
func Exec(ctx context.Context, tool string, args []string, env []string) (string, error) {
	bin, ok := binpath.Lookup(tool)
	if !ok {
		return "", fmt.Errorf("%s isn't installed at a known system path", tool)
	}
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- a fixed system path; arguments are validated names, never shell text
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	hideWindow(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return stdout.String(), &ExitError{Tool: tool, Code: ee.ExitCode(), Stderr: limit(stderr.String(), 512)}
	}
	return stdout.String(), err
}

func limit(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// currentUser is the account the agent runs as ("" when unknown).
var currentUser = func() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return bareName(u.Username)
}
