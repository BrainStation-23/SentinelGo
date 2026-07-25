//go:build linux

package epm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LaunchResult identifies a process started by LaunchAsUser.
type LaunchResult struct {
	ProcessID uint32
}

// sessionEnvKeys are the environment variables copied from a live process
// owned by the target user into the launched process's environment, so a
// root-privileged GUI application can actually connect to that user's
// X11/Wayland display and session bus.
//
// XDG_SESSION_TYPE and XDG_CURRENT_DESKTOP are included alongside the
// display/bus variables because many GTK/Qt applications and the
// xdg-desktop-portal machinery (file choosers, notifications) branch on
// these explicitly to pick their Wayland vs. X11 backend and portal
// implementation — without them, a Wayland-native app can behave oddly or
// silently fall back to a nonfunctional X11 path even with WAYLAND_DISPLAY
// correctly set. This has not been validated against a real Wayland
// compositor in this codebase's test environment (see the Operator Guide's
// Limitations section); this is a defensive improvement based on how these
// variables are documented to be used, not something confirmed by live
// testing on a GNOME/KDE Wayland session.
var sessionEnvKeys = []string{
	"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
	"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "HOME",
	"XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP",
}

// LaunchAsUser starts appPath (with optional extra arguments), running with
// this daemon's own (root) privileges — the practical "elevation" semantics
// EPM needs — while attaching to the GUI session belonging to uid/username,
// so its windows appear on that user's desktop.
//
// Unlike a traditional "drop privilege" pattern (fork+setresuid+execve),
// this deliberately keeps the process privileged: the whole point of EPM is
// granting a specific, policy-approved elevated capability to a standard
// user's desktop, not stepping the daemon down to their level. It is the
// direct Linux analogue of launcher_windows.go's CreateProcessAsUser (which
// grants an elevated token) and launcher_darwin.go's `launchctl asuser`
// (which keeps root while attaching to the user's session).
//
// Session environment (DISPLAY, XAUTHORITY, WAYLAND_DISPLAY,
// DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR) is recovered by reading
// /proc/<pid>/environ from a live process already running as uid with a
// display set — root can read any process's environ, and this avoids
// depending on any particular desktop environment's own IPC/session API.
//
// Callers must only reach this after Engine.Evaluate has already returned
// Allowed for the request — this function performs no policy checks itself.
func LaunchAsUser(uid uint32, username, appPath string, args []string) (*LaunchResult, error) {
	sessionEnv, err := findSessionEnviron(uid)
	if err != nil {
		return nil, fmt.Errorf("resolve GUI session environment: %w", err)
	}

	cmd := exec.Command(appPath, args...)
	cmd.Env = buildLaunchEnviron(sessionEnv, username)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}
	// Fire-and-forget, matching the Windows/macOS launchers: we only need the
	// process's existence for the audit record, not its lifetime. We still
	// must Wait() eventually so the child doesn't become a zombie.
	go func() { _ = cmd.Wait() }()

	return &LaunchResult{ProcessID: uint32(cmd.Process.Pid)}, nil
}

// buildLaunchEnviron starts from this daemon's own environment (so PATH and
// similar are sane), layers in the target user's session variables, and sets
// USER/LOGNAME/HOME to that user's identity for application compatibility.
func buildLaunchEnviron(sessionEnv map[string]string, username string) []string {
	env := append([]string{}, os.Environ()...)
	for _, key := range sessionEnvKeys {
		if v, ok := sessionEnv[key]; ok && v != "" {
			env = append(env, key+"="+v)
		}
	}
	env = append(env, "USER="+username, "LOGNAME="+username)
	return env
}

// findSessionEnviron scans /proc for a process owned by uid whose
// environment includes a display variable (DISPLAY or WAYLAND_DISPLAY),
// returning the small set of variables a new process needs to join that
// user's GUI session.
func findSessionEnviron(uid uint32) (map[string]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		if !ownedByUID(pid, uid) {
			continue
		}

		env, err := readProcEnviron(pid)
		if err != nil {
			continue // permission denied / process exited mid-scan; try the next one
		}

		if env["DISPLAY"] != "" || env["WAYLAND_DISPLAY"] != "" {
			return env, nil
		}
	}

	return nil, fmt.Errorf("no GUI session environment found for uid %d (is a desktop session running?)", uid)
}

func ownedByUID(pid int, uid uint32) bool {
	info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid
}

// readProcEnviron reads and parses /proc/<pid>/environ.
func readProcEnviron(pid int) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, err
	}
	return parseEnviron(data), nil
}

// parseEnviron parses the NUL-separated KEY=VALUE entries found in a
// /proc/<pid>/environ file into a map.
func parseEnviron(data []byte) map[string]string {
	env := make(map[string]string)
	for _, entry := range strings.Split(string(data), "\x00") {
		if entry == "" {
			continue
		}
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		env[key] = value
	}
	return env
}
