package persistence

import (
	"encoding/json"
	"strings"
)

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS.

// ── Windows: Get-ScheduledTask ──────────────────────────────────────────────

type windowsTaskRow struct {
	Name    string `json:"Name"`
	Path    string `json:"Path"`
	Command string `json:"Command"`
	Enabled bool   `json:"Enabled"`
}

// parseWindowsTasks parses the Get-ScheduledTask script's JSON. A single
// task serializes as a bare object rather than a one-element array, the same
// ambiguity handled throughout this codebase's other PowerShell-JSON call
// sites.
func parseWindowsTasks(output string) ([]windowsTaskRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsTaskRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsTaskRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsTaskRow{single}, nil
}

// ── Linux: systemctl show ───────────────────────────────────────────────────

// parseSystemctlShow parses `systemctl show '*.service' -p Id -p ExecStart
// -p FragmentPath -p UnitFileState`'s output: properties for every matched
// unit are concatenated back-to-back with no separator other than a new "Id="
// line marking the start of the next unit — this splits on that marker.
func parseSystemctlShow(output string) []Entry {
	var entries []Entry
	var current map[string]string

	flush := func() {
		if current == nil {
			return
		}
		id := current["Id"]
		if id == "" {
			return
		}
		enabled := current["UnitFileState"] == "enabled"
		entries = append(entries, Entry{
			Type:     "systemd_service",
			Name:     id,
			Command:  execStartCommand(current["ExecStart"]),
			Location: current["FragmentPath"],
			Enabled:  &enabled,
		})
	}

	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		if key == "Id" {
			flush()
			current = make(map[string]string)
		}
		if current == nil {
			continue
		}
		current[key] = val
	}
	flush()

	return entries
}

// execStartCommand extracts a readable command from systemd's ExecStart
// property, which prints as a struct-ish string like
// "{ path=/usr/bin/foo ; argv[]=/usr/bin/foo --bar ; ... }" rather than a
// plain command line.
func execStartCommand(raw string) string {
	idx := strings.Index(raw, "argv[]=")
	if idx < 0 {
		return raw
	}
	rest := raw[idx+len("argv[]="):]
	if end := strings.Index(rest, " ;"); end >= 0 {
		return strings.TrimSpace(rest[:end])
	}
	return strings.TrimSpace(rest)
}

// ── Linux/macOS: crontab-style files ────────────────────────────────────────

// parseCrontab parses a crontab-family file's job lines. systemCrontab
// selects the format: /etc/crontab and /etc/cron.d/* carry an extra *user*
// field (minute hour dom month dow user command) that a per-user crontab
// (/var/spool/cron/<user> or macOS's /var/at/tabs/<user>) does not (minute
// hour dom month dow command) — conflating the two silently drops the first
// word of the command or misreads a username as part of it.
func parseCrontab(content string, systemCrontab bool, location string) []Entry {
	var entries []Entry
	minCommandFields := 6
	if systemCrontab {
		minCommandFields = 7
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 && !strings.ContainsAny(line[:idx], " \t") {
			continue // MAILTO=, PATH=, SHELL= style variable assignment
		}

		fields := strings.Fields(line)
		if len(fields) < minCommandFields {
			continue
		}

		command := strings.Join(fields[minCommandFields-1:], " ")
		enabled := true
		entries = append(entries, Entry{
			Type:     "cron",
			Name:     command,
			Command:  command,
			Location: location,
			Enabled:  &enabled,
		})
	}
	return entries
}

// ── macOS: launchd (plutil-converted JSON) ──────────────────────────────────

type launchdPlist struct {
	Label            string   `json:"Label"`
	ProgramArguments []string `json:"ProgramArguments"`
	Program          string   `json:"Program"`
	Disabled         *bool    `json:"Disabled"`
}

// parseLaunchdPlist parses one plist already converted to JSON via
// `plutil -convert json -o -`.
func parseLaunchdPlist(output, path string) (Entry, bool) {
	var p launchdPlist
	if err := json.Unmarshal([]byte(output), &p); err != nil {
		return Entry{}, false
	}
	if p.Label == "" {
		return Entry{}, false
	}

	command := p.Program
	if command == "" && len(p.ProgramArguments) > 0 {
		command = strings.Join(p.ProgramArguments, " ")
	}

	enabled := true
	if p.Disabled != nil {
		enabled = !*p.Disabled
	}

	return Entry{
		Type:     "launchd",
		Name:     p.Label,
		Command:  command,
		Location: path,
		Enabled:  &enabled,
	}, true
}

// isAppleOwnedLaunchdLabel filters Apple's own several-hundred-entry set,
// the same recommendation docs/telemetry/03-collection-matrix.md makes for
// launchd generally ("skipping /System/Library/* and com.apple.* labels cuts
// 250+ files to typically 10–40").
func isAppleOwnedLaunchdLabel(label string) bool {
	return strings.HasPrefix(label, "com.apple.")
}
