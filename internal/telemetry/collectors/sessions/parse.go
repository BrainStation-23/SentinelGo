package sessions

import (
	"encoding/json"
	"strings"
)

// This file holds every platform's text/JSON parsing as pure functions with
// no build tag, so the parsing logic — the part most likely to have a subtle
// bug — is unit tested on every host regardless of GOOS, the same pattern
// used throughout internal/osinfo/*/parse.go and the other C1 collectors.

// ── Windows: quser ──────────────────────────────────────────────────────────

// parseQuser parses `quser` (query user) output into sessions.
//
// quser's columns are fixed-width in a way plain whitespace-splitting cannot
// handle reliably: a disconnected session leaves SESSIONNAME blank, which
// shifts where a naive split would land the remaining fields. This instead
// locates each column's start offset from the header line itself — tolerant
// of the exact spacing varying across Windows versions — and slices every
// data row at those fixed offsets.
func parseQuser(output string) []Session {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil
	}

	header := lines[0]
	userIdx := strings.Index(header, "USERNAME")
	sessIdx := strings.Index(header, "SESSIONNAME")
	idIdx := strings.Index(header, "ID")
	stateIdx := strings.Index(header, "STATE")
	idleIdx := strings.Index(header, "IDLE TIME")

	// USERNAME and STATE are the two columns every quser version has printed;
	// without them the format is not what this parser expects.
	if userIdx < 0 || stateIdx < 0 {
		return nil
	}

	slice := func(line string, start, end int) string {
		if start < 0 || start >= len(line) {
			return ""
		}
		if end < 0 || end > len(line) {
			end = len(line)
		}
		if end <= start {
			return ""
		}
		return strings.TrimSpace(line[start:end])
	}

	var sessions []Session
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}

		username := slice(line, userIdx, sessIdx)
		if username == "" {
			continue
		}

		sessionName := ""
		if sessIdx >= 0 {
			sessionName = slice(line, sessIdx, idIdx)
		}

		state := slice(line, stateIdx, idleIdx)

		sessions = append(sessions, Session{
			Username:    username,
			SessionName: sessionName,
			SessionType: classifyWindowsSessionName(sessionName),
			Remote:      isWindowsRemoteSession(sessionName),
			State:       state,
		})
	}
	return sessions
}

// classifyWindowsSessionName maps a quser SESSIONNAME to a normalised
// session type.
func classifyWindowsSessionName(sessionName string) string {
	switch {
	case sessionName == "":
		// A logged-in user with no attached session — quser reports this for
		// a disconnected RDP session, the common case.
		return "disconnected"
	case strings.EqualFold(sessionName, "console"):
		return "console"
	case strings.Contains(strings.ToLower(sessionName), "rdp-tcp"):
		return "rdp"
	default:
		return "other"
	}
}

// isWindowsRemoteSession reports whether sessionName indicates a session
// whose input does not originate at this device's physical console.
func isWindowsRemoteSession(sessionName string) bool {
	// A disconnected session's prior transport is not recoverable from quser
	// alone; treating it as remote would be a guess, so it is reported as
	// non-remote by default rather than fabricated. SessionType still records
	// "disconnected" distinctly, so this is not lost information.
	return classifyWindowsSessionName(sessionName) == "rdp"
}

// ── Linux: loginctl ──────────────────────────────────────────────────────────

// loginctlSession is one entry from `loginctl list-sessions -o json`.
type loginctlSession struct {
	Session string `json:"session"`
	User    string `json:"user"`
	Seat    string `json:"seat"`
}

// parseLoginctlList parses `loginctl list-sessions -o json` output.
func parseLoginctlList(output string) ([]loginctlSession, error) {
	var sessions []loginctlSession
	if err := json.Unmarshal([]byte(output), &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// parseKeyEqualsValue parses systemd's "Key=Value" per-line property output,
// as printed by `loginctl show-session ... -p Key1 -p Key2`.
func parseKeyEqualsValue(output string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		out[key] = val
	}
	return out
}

// classifyLoginctlSession derives a session type and remote flag from a
// session's seat and its systemd Remote property.
//
// A session with Remote=yes (systemd's own classification, typically an SSH
// pty) is "ssh". A session attached to a seat and not remote is the physical
// console. Anything else (a screen/tmux/cron-spawned session with no seat) is
// "other" rather than guessed.
func classifyLoginctlSession(seat, remoteProp string) (sessionType string, remote bool) {
	if strings.EqualFold(strings.TrimSpace(remoteProp), "yes") {
		return "ssh", true
	}
	if strings.TrimSpace(seat) != "" {
		return "console", false
	}
	return "other", false
}

// ── macOS: who ───────────────────────────────────────────────────────────────

// parseWho parses `who` output into sessions. Columns are whitespace
// separated; username and tty never contain spaces, so simple field
// splitting is safe here (unlike quser's fixed-width columns).
func parseWho(output string) []Session {
	var sessions []Session
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		username := fields[0]
		tty := fields[1]

		// A trailing "(host)" token is who's own marker for a remote login.
		remote := false
		if last := fields[len(fields)-1]; strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
			remote = true
		}

		sessions = append(sessions, Session{
			Username:    username,
			SessionName: tty,
			SessionType: classifyDarwinSession(tty, remote),
			Remote:      remote,
		})
	}
	return sessions
}

// classifyDarwinSession maps a who tty and remote flag to a normalised
// session type.
func classifyDarwinSession(tty string, remote bool) string {
	if strings.EqualFold(tty, "console") {
		return "console"
	}
	if remote {
		return "ssh"
	}
	return "terminal"
}
