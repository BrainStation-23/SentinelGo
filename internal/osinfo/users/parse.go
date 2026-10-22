package users

// parse.go contains pure string-to-struct parse functions extracted from each
// platform's getLocalUsers implementation. No OS suffix means they compile on
// every platform and can be unit-tested without running OS commands.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// ── Linux account state (#172) ───────────────────────────────────────────────

// shadowEntry is the account state read from /etc/shadow.
type shadowEntry struct {
	Locked     bool // password field starts with "!" (passwd -l / usermod -L)
	LastChange int  // days since 1970-01-01; -1 unknown, 0 = must change at next login
	Expire     int  // account expiry, days since 1970-01-01; -1 never
}

func parseShadow(content string) map[string]shadowEntry {
	out := map[string]shadowEntry{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) < 8 || f[0] == "" {
			continue
		}
		out[f[0]] = shadowEntry{
			Locked:     strings.HasPrefix(f[1], "!"),
			LastChange: atoiOr(f[2], -1),
			Expire:     atoiOr(f[7], -1),
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// shadowDay converts a shadow day count to a time.
func shadowDay(days int) time.Time {
	return time.Unix(int64(days)*86400, 0).UTC()
}

// linuxAccountState is the account state derived from a shadow entry.
// ChangedAt is when the password was last changed, as ISO 8601 UTC ("" when
// unknown or forced to change at next login).
type linuxAccountState struct {
	Enabled   bool // not locked and not expired
	ChangedAt string
}

func accountStateFromShadow(e shadowEntry, now time.Time) linuxAccountState {
	expired := e.Expire >= 0 && !shadowDay(e.Expire).After(now)
	st := linuxAccountState{Enabled: !e.Locked && !expired}
	if e.LastChange > 0 {
		st.ChangedAt = shared.ISOTime(shadowDay(e.LastChange))
	}
	return st
}

// lastlogLayout is the "Latest" column of `lastlog` run under LC_ALL=C.
const lastlogLayout = "Mon Jan _2 15:04:05 -0700 2006"

// parseLastlog parses `LC_ALL=C lastlog` (or lastlog2) output into each
// user's last logon. "**Never logged in**" maps to NeverLoggedOn. Port and
// From may be blank, so the date is taken from the last six fields.
func parseLastlog(output string) map[string]*shared.LastLogon {
	out := map[string]*shared.LastLogon{}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "Username" {
			continue
		}
		if strings.Contains(line, "**Never logged in**") {
			out[f[0]] = shared.NeverLoggedOn()
			continue
		}
		if len(f) < 7 {
			continue
		}
		if t, err := time.Parse(lastlogLayout, strings.Join(f[len(f)-6:], " ")); err == nil {
			out[f[0]] = shared.LoggedOnAt(t)
		}
	}
	return out
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

// parseDarwinAccountEnabled reads `dscl . read /Users/<name>
// AuthenticationAuthority`: a disabled account carries ";DisabledUser;".
// ok is false when the attribute wasn't printed (dscl says "No such key:
// AuthenticationAuthority" then).
func parseDarwinAccountEnabled(output string) (enabled, ok bool) {
	if !strings.HasPrefix(strings.TrimSpace(output), "AuthenticationAuthority:") {
		return false, false
	}
	return !strings.Contains(output, "DisabledUser"), true
}

// parseDarwinPasswordLastSet reads `dscl . read /Users/<name>
// accountPolicyData`, a plist whose passwordLastSetTime is Unix seconds.
func parseDarwinPasswordLastSet(output string) (time.Time, bool) {
	root, ok := shared.PlistFromOutput(output)
	if !ok {
		return time.Time{}, false
	}
	dict, _ := root.(map[string]any)
	sec, ok := shared.PlistNumber(dict["passwordLastSetTime"])
	if !ok || sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0), true
}

// parseDarwinIDGroups parses `id -Gn <username>` output.
// The output is space-separated group names on a single line.
func parseDarwinIDGroups(output string) []string {
	return strings.Fields(strings.TrimSpace(output))
}

// ── Windows ───────────────────────────────────────────────────────────────────

// parseWindowsUsersJSON parses the JSON output of a Win32_UserAccount query.
// PowerShell returns a bare object (not an array) when there is exactly one
// account, so both forms are handled. Built-in accounts (Administrator,
// Guest, …) are reported with IsBuiltin, since an enabled one is what
// compliance checks look for (#223); setup's sandbox accounts (defaultuser0,
// defaultuser1 …) are left out.
func parseWindowsUsersJSON(output string) []shared.UserWithGroup {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &rows); err != nil {
		var single map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(output)), &single) != nil {
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
		if strings.HasPrefix(strings.ToLower(name), "defaultuser") {
			continue
		}
		sid := ""
		if v, ok := row["SID"]; ok {
			sid = fmt.Sprintf("%v", v)
		}
		result = append(result, shared.UserWithGroup{
			Username:  name,
			UID:       sid,
			IsBuiltin: isWindowsBuiltinSID(sid),
		})
	}
	return result
}

// windowsUserExtras is one Get-LocalUser row, keyed by SID in
// parseWindowsUserExtrasJSON.
type windowsUserExtras struct {
	Enabled         *bool
	LastLogon       *shared.LastLogon
	PasswordLastSet string
}

// parseWindowsUserExtrasJSON parses userExtrasScript's output. Times are
// Unix seconds; LastLogon present but null means "never logged on", which
// is kept distinct from a missing key ("unknown").
func parseWindowsUserExtrasJSON(output string) map[string]windowsUserExtras {
	var rows []map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(output)), &rows) != nil {
		return nil
	}
	out := map[string]windowsUserExtras{}
	for _, row := range rows {
		sid, _ := row["SID"].(string)
		if sid == "" {
			continue
		}
		var e windowsUserExtras
		if b, ok := row["Enabled"].(bool); ok {
			e.Enabled = &b
		}
		if v, present := row["LastLogon"]; present {
			if sec, ok := unixSeconds(v); ok {
				e.LastLogon = shared.LoggedOnAt(sec)
			} else if v == nil {
				e.LastLogon = shared.NeverLoggedOn()
			}
		}
		if sec, ok := unixSeconds(row["PasswordLastSet"]); ok {
			e.PasswordLastSet = shared.ISOTime(sec)
		}
		out[sid] = e
	}
	return out
}

// unixSeconds converts a decoded JSON number of Unix seconds to a time.
func unixSeconds(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok || f <= 0 {
		return time.Time{}, false
	}
	n, ok := shared.JSONInt(f)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(n), 0), true
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
