package patches

import (
	"encoding/json"
	"strings"
)

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS.

// ── Windows ──────────────────────────────────────────────────────────────────

type windowsPendingRow struct {
	ID          string `json:"ID"`
	Description string `json:"Description"`
	Category    string `json:"Category"`
}

// parseWindowsPending parses the Windows Update COM search script's JSON. A
// single pending update serializes as a bare object rather than a
// one-element array, the same ambiguity handled throughout this codebase's
// other PowerShell-JSON call sites.
func parseWindowsPending(output string) ([]windowsPendingRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsPendingRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsPendingRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsPendingRow{single}, nil
}

// ── Linux: dpkg.log (installed, Debian) ─────────────────────────────────────

// parseDpkgLog scans dpkg.log lines for "status installed" entries. dpkg's
// timestamps are already "YYYY-MM-DD HH:MM:SS", locale-independent, unlike
// quser/softwareupdate — safe to combine into an RFC3339-shaped string
// directly.
func parseDpkgLog(output string) []Update {
	var updates []Update
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[2] != "status" || fields[3] != "installed" {
			continue
		}
		pkg := fields[4]
		if idx := strings.Index(pkg, ":"); idx >= 0 {
			pkg = pkg[:idx] // strip :amd64-style architecture suffix
		}
		version := ""
		if len(fields) > 5 {
			version = fields[5]
		}
		updates = append(updates, Update{
			ID:          pkg,
			Description: strings.TrimSpace(pkg + " " + version),
			Category:    "package",
			Status:      "installed",
			InstalledOn: fields[0] + "T" + fields[1],
		})
	}
	return updates
}

// ── Linux: rpm -qa --last (installed, RPM-based) ────────────────────────────

// parseRpmLast parses `rpm -qa --last`, whose rows are
// "<name-version-release>    <date>" separated by 2+ spaces (the same
// fixed-column-ish convention this codebase already handles for quser).
// The date is passed through as-is rather than parsed: rpm renders it in the
// host's locale, the same trap already avoided for quser/who.
func parseRpmLast(output string) []Update {
	var updates []Update
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		idx := strings.Index(line, "  ")
		if idx < 0 {
			continue
		}
		pkg := strings.TrimSpace(line[:idx])
		date := strings.TrimSpace(line[idx:])
		if pkg == "" {
			continue
		}
		updates = append(updates, Update{
			ID:          pkg,
			Description: pkg,
			Category:    "package",
			Status:      "installed",
			InstalledOn: date,
		})
	}
	return updates
}

// ── Linux: apt list --upgradable (pending, Debian) ──────────────────────────

// parseAptUpgradable parses `apt list --upgradable` rows, formatted
// "package/suite version arch [upgradable from: old-version]". The leading
// "Listing..." status line (and any warning banner) is skipped by requiring
// a "/" in the first field.
func parseAptUpgradable(output string) []Update {
	var updates []Update
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		nameParts := strings.SplitN(fields[0], "/", 2)
		if len(nameParts) != 2 {
			continue
		}
		updates = append(updates, Update{
			ID:          nameParts[0],
			Description: strings.TrimSpace(line),
			Category:    "package",
			Status:      "pending",
		})
	}
	return updates
}

// ── Linux: dnf/yum check-update (pending, RPM-based) ────────────────────────

// parseCheckUpdate parses `dnf check-update`/`yum check-update` output: after
// a blank-line-separated header, each row is "name.arch  version  repo"
// separated by runs of whitespace.
func parseCheckUpdate(output string) []Update {
	var updates []Update
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Header/status lines ("Last metadata expiration check...") don't
		// look like "name.arch  version" — require a dot in the first field
		// to filter them out without an explicit allow-list of headers.
		if !strings.Contains(fields[0], ".") {
			continue
		}
		updates = append(updates, Update{
			ID:          fields[0],
			Description: strings.TrimSpace(line),
			Category:    "package",
			Status:      "pending",
		})
	}
	return updates
}

// ── macOS: softwareupdate ────────────────────────────────────────────────────

// parseSoftwareupdateHistory parses `softwareupdate --history`'s
// "* Name" / indented-date-line pairs.
func parseSoftwareupdateHistory(output string) []Update {
	var updates []Update
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "*") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "*"))
		if name == "" {
			continue
		}
		installedOn := ""
		if i+1 < len(lines) {
			next := strings.TrimSpace(lines[i+1])
			if next != "" && !strings.HasPrefix(next, "*") {
				installedOn = next
			}
		}
		updates = append(updates, Update{
			ID:          name,
			Description: name,
			Category:    "software",
			Status:      "installed",
			InstalledOn: installedOn,
		})
	}
	return updates
}

// parseSoftwareupdateList parses `softwareupdate -l`'s "* Label: ..." lines.
func parseSoftwareupdateList(output string) []Update {
	var updates []Update
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "* Label:") && !strings.HasPrefix(line, "*Label:") {
			continue
		}
		label := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "* Label:"), "*Label:"))
		if label == "" {
			continue
		}
		updates = append(updates, Update{
			ID:          label,
			Description: label,
			Category:    "software",
			Status:      "pending",
		})
	}
	return updates
}
