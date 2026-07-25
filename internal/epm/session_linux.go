//go:build linux

package epm

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ConsoleUser returns the UID and username of the user in the currently
// active (focused) systemd-logind session — the Linux analogue of Windows'
// active console session and macOS's console user. Determined via
// `loginctl`, which is present on the overwhelming majority of modern
// distributions (Ubuntu, Debian, Fedora, RHEL/CentOS, Arch, openSUSE, ...);
// no libpam binding or raw utmp parsing is used, so behavior does not depend
// on a specific glibc struct layout.
//
// On a non-systemd distribution (no logind), this returns an error — a known
// limitation consistent with the "no cgo" rule: reading /var/run/utmp
// directly would require depending on a struct layout that is not portable
// across distributions and could silently misparse rather than fail loudly.
func ConsoleUser() (uid uint32, username string, err error) {
	sessionID, err := activeSessionID()
	if err != nil {
		return 0, "", err
	}
	return resolveSessionUser(sessionID)
}

// SessionForPID resolves the systemd-logind session UID and username for the
// process pid belongs to — not restricted to the currently "active" (focused)
// session the way ConsoleUser is, so a user connected via any genuine
// interactive login (a second concurrent session, a non-focused desktop, a
// screen-shared session) can still use EPM, matching how pipe_windows.go
// resolves the connecting client's own session via ProcessIdToSessionId
// rather than assuming "the active console session". Session membership is
// read from /proc/<pid>/environ's XDG_SESSION_ID, which systemd-logind sets
// for every process spawned within a login session.
func SessionForPID(pid uint32) (uid uint32, username string, err error) {
	env, err := readProcEnviron(int(pid))
	if err != nil {
		return 0, "", fmt.Errorf("read /proc/%d/environ: %w", pid, err)
	}
	sessionID := env["XDG_SESSION_ID"]
	if sessionID == "" {
		return 0, "", fmt.Errorf("pid %d has no XDG_SESSION_ID (not in an interactive logind session)", pid)
	}

	class, err := sessionProperty(sessionID, "Class")
	if err != nil || class != "user" {
		// Same defensive check as activeSessionID: only a genuine
		// interactive login session (Class=user) is a valid identity source.
		return 0, "", fmt.Errorf("session %s is not an interactive user session", sessionID)
	}

	return resolveSessionUser(sessionID)
}

// resolveSessionUser reads the User (UID) and Name (username) properties of
// a systemd-logind session.
func resolveSessionUser(sessionID string) (uid uint32, username string, err error) {
	uidStr, err := sessionProperty(sessionID, "User")
	if err != nil {
		return 0, "", fmt.Errorf("resolve session user: %w", err)
	}
	uid64, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("parse session uid %q: %w", uidStr, err)
	}

	username, err = sessionProperty(sessionID, "Name")
	if err != nil {
		return 0, "", fmt.Errorf("resolve session username: %w", err)
	}
	if username == "" {
		return 0, "", fmt.Errorf("empty username for session %s", sessionID)
	}

	return uint32(uid64), username, nil
}

// activeSessionID finds the systemd-logind session currently marked "active"
// (has input focus) among all logged-in sessions — relevant on multi-session
// machines (fast user switching, multiple ttys/seats).
//
// Filtering on State=active alone is not sufficient: confirmed by testing
// against a real (WSL2) Linux instance, logind can mark an early-boot
// system/init session as "active" (Class=user-early) when no human has
// actually logged in — there, ConsoleUser() would otherwise silently resolve
// to root. Requiring Class=user as well excludes that and every other
// non-interactive session class logind defines (greeter, lock-screen,
// background, manager, manager-early, none), leaving only genuine
// interactive user logins.
func activeSessionID() (string, error) {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend", "--no-pager").Output()
	if err != nil {
		return "", fmt.Errorf("loginctl list-sessions: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		sessionID := fields[0]

		state, err := sessionProperty(sessionID, "State")
		if err != nil {
			continue // session may have exited between listing and querying
		}
		if state != "active" {
			continue
		}
		class, err := sessionProperty(sessionID, "Class")
		if err != nil || class != "user" {
			continue // not a genuine interactive login (see comment above)
		}
		return sessionID, nil
	}

	return "", fmt.Errorf("no active interactive logind session found")
}

// sessionProperty runs `loginctl show-session <id> -p <property> --value`,
// returning just the property's value (no "Property=" prefix to parse off).
func sessionProperty(sessionID, property string) (string, error) {
	out, err := exec.Command("loginctl", "show-session", sessionID, "--no-pager", "-p", property, "--value").Output()
	if err != nil {
		return "", fmt.Errorf("loginctl show-session %s -p %s: %w", sessionID, property, err)
	}
	return strings.TrimSpace(string(out)), nil
}
