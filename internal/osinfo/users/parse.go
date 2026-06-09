package users

// parse.go contains pure string-to-struct parse functions extracted from each
// platform's getLocalUsers implementation. No OS suffix means they compile on
// every platform and can be unit-tested without running OS commands.

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// ── Linux ─────────────────────────────────────────────────────────────────────

// parsePasswdContent parses /etc/passwd and returns human user accounts.
// Filtered out: root (uid 0), system-prefix accounts (_), service account name
// patterns (nobody/system/daemon), and accounts whose home directory is not
// under /home/.
func parsePasswdContent(content string) []shared.UserWithGroup {
	var result []shared.UserWithGroup
	for _, line := range strings.Split(content, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid := parts[2]
		gid := parts[3]
		homeDir := parts[5]
		shell := strings.TrimRight(parts[6], "\r\n")

		if uid == "0" || strings.HasPrefix(username, "_") ||
			strings.Contains(username, "nobody") ||
			strings.Contains(username, "system") ||
			strings.Contains(username, "daemon") {
			continue
		}
		if homeDir == "" || homeDir == "/" || !strings.HasPrefix(homeDir, "/home/") {
			continue
		}
		result = append(result, shared.UserWithGroup{
			Username: username,
			UID:      uid,
			GID:      gid,
			HomeDir:  homeDir,
			Shell:    shell,
		})
	}
	return result
}

// parseLinuxGroupOutput parses the output of `groups <username>`.
// GNU coreutils formats the output as "username : group1 group2 …"; other
// implementations omit the prefix. Both forms are handled by stripping any
// "username : " or "username: " prefix before splitting.
func parseLinuxGroupOutput(output, username string) []string {
	text := strings.TrimSpace(output)
	if prefix := username + " : "; strings.HasPrefix(text, prefix) {
		text = text[len(prefix):]
	} else if prefix := username + ": "; strings.HasPrefix(text, prefix) {
		text = text[len(prefix):]
	}
	return strings.Fields(text)
}

// ── Darwin ────────────────────────────────────────────────────────────────────

// parseDarwinUserList parses `dscl . list /Users` output.
// System accounts beginning with "_" and known service account names are
// filtered out.
func parseDarwinUserList(output string) []string {
	var result []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "_") ||
			line == "nobody" || line == "root" || line == "daemon" || line == "Guest" {
			continue
		}
		result = append(result, line)
	}
	return result
}

// parseDarwinProperty parses `dscl . read /Users/<name> <Property>` output.
// The output is either "PropertyName: value" or "PropertyName:\n value" —
// both are handled by splitting on the first ":" and trimming whitespace.
func parseDarwinProperty(output string) string {
	parts := strings.SplitN(strings.TrimSpace(output), ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// parseDarwinIDGroups parses `id -Gn <username>` output.
// The output is space-separated group names on a single line.
func parseDarwinIDGroups(output string) []string {
	return strings.Fields(strings.TrimSpace(output))
}

// ── Windows ───────────────────────────────────────────────────────────────────

// windowsSystemAccounts are local accounts built into Windows that should be
// excluded from the user inventory.
var windowsSystemAccounts = map[string]bool{
	"administrator":      true,
	"guest":              true,
	"defaultaccount":     true,
	"wdagutilityaccount": true,
}

// parseWindowsUsersJSON parses the JSON output of a Win32_UserAccount query.
// PowerShell returns a bare object (not an array) when there is exactly one
// account, so both forms are handled. Built-in system accounts and sandbox
// accounts (defaultuser0, defaultuser1 …) are excluded.
func parseWindowsUsersJSON(output string) []shared.UserWithGroup {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &rows); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal([]byte(strings.TrimSpace(output)), &single); err2 != nil {
			return nil
		}
		rows = []map[string]any{single}
	}

	var result []shared.UserWithGroup
	for _, row := range rows {
		name, _ := row["Name"].(string)
		if name == "" {
			continue
		}
		nameLower := strings.ToLower(name)
		if windowsSystemAccounts[nameLower] || strings.HasPrefix(nameLower, "defaultuser") {
			continue
		}
		sid := ""
		if v, ok := row["SID"]; ok {
			sid = fmt.Sprintf("%v", v)
		}
		result = append(result, shared.UserWithGroup{
			Username: name,
			UID:      sid,
		})
	}
	return result
}

// parseWindowsGroupLines parses newline-separated group names from PowerShell
// output, trimming whitespace and skipping blank lines.
func parseWindowsGroupLines(output string) []string {
	var groups []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			groups = append(groups, line)
		}
	}
	return groups
}
