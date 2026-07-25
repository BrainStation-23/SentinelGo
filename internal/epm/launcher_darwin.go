//go:build darwin

package epm

import (
	"fmt"
	"os/exec"
	"strconv"
)

// LaunchResult identifies a process started by LaunchAsUser.
type LaunchResult struct {
	ProcessID uint32
}

// LaunchAsUser starts appPath (with optional extra arguments) attached to the
// GUI session of the user identified by uid, while the process itself
// retains this daemon's own (root) privileges — the practical "elevation"
// semantics EPM needs on macOS: a process the standard user could not have
// started with these privileges themselves, rendered on their own desktop.
//
// This shells out to `launchctl asuser <uid> <path> [args...]`, the
// supported, non-deprecated way for a root daemon to run a process inside a
// specific user's per-user launchd/GUI bootstrap context (so its windows
// appear on that user's desktop) without changing the process's UID.
// Deliberately avoids the deprecated AuthorizationExecuteWithPrivileges API
// and Authorization Services / Security.framework bindings, both of which
// would require cgo (CLAUDE.md's hard no-cgo rule) — `launchctl` is a
// subprocess to the OS's own CLI, exactly the sanctioned alternative.
//
// Callers must only reach this after Engine.Evaluate has already returned
// Allowed for the request — this function performs no policy checks itself.
func LaunchAsUser(uid uint32, appPath string, args []string) (*LaunchResult, error) {
	cmdArgs := append([]string{"asuser", strconv.FormatUint(uint64(uid), 10), appPath}, args...)

	cmd := exec.Command("launchctl", cmdArgs...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("launchctl asuser: %w", err)
	}

	// Fire-and-forget, matching the Windows launcher: we only need the
	// process's existence for the audit record, not its lifetime. We still
	// must Wait() eventually so the child doesn't become a zombie.
	go func() { _ = cmd.Wait() }()

	// launchctl re-execs into the target bootstrap context and then execs
	// the given command as its own child, so cmd.Process.Pid identifies the
	// launchctl wrapper, not the application itself — the actual app PID is
	// a grandchild we cannot see without further introspection. This mirrors
	// codesign_windows.go's CryptMsgGetParam gap: a known, documented Phase 2
	// simplification rather than an oversight.
	return &LaunchResult{ProcessID: uint32(cmd.Process.Pid)}, nil
}
