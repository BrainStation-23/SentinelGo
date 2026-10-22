package users

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// usersDir is the macOS directory holding per-user home directories, used
// both as the dscl node path prefix and to sanity-check NFSHomeDirectory.
const usersDir = "/Users/"

func getLocalUsers() []shared.UserWithGroup {
	output, err := shared.RunCommand("dscl", ".", "list", "/Users")
	if err != nil {
		return nil
	}

	var result []shared.UserWithGroup
	for _, username := range parseDarwinUserList(output) {
		homeOut, err := shared.RunCommand("dscl", ".", "read", usersDir+username, "NFSHomeDirectory")
		if err != nil || !strings.Contains(homeOut, usersDir) {
			continue
		}

		var groups []string
		if groupOut, err := shared.RunCommand("id", "-Gn", username); err == nil {
			groups = parseDarwinIDGroups(groupOut)
		}

		u := shared.UserWithGroup{
			Username: username,
			Groups:   groups,
			UID:      getUserProperty(username, "UniqueID"),
			GID:      getUserProperty(username, "PrimaryGroupID"),
			HomeDir:  parseDarwinProperty(homeOut),
			Shell:    getUserProperty(username, "UserShell"),
		}
		applyDarwinAccountState(&u)
		result = append(result, u)
	}
	return result
}

// applyDarwinAccountState adds is_enabled and password_last_set (#172), and
// last_logon from the login records (#223). macOS rotates those records, so
// last_logon is left out when a user has none, rather than reported as never.
func applyDarwinAccountState(u *shared.UserWithGroup) {
	u.LastLogon = darwinLastLogon(u.Username)
	if out, err := shared.RunCommand("dscl", ".", "read", usersDir+u.Username, "AuthenticationAuthority"); err == nil {
		if enabled, ok := parseDarwinAccountEnabled(out); ok {
			u.IsEnabled = &enabled
		}
	}
	if out, err := shared.RunCommand("dscl", ".", "read", usersDir+u.Username, "accountPolicyData"); err == nil {
		if t, ok := parseDarwinPasswordLastSet(out); ok {
			u.PasswordLastSet = shared.ISOTime(t)
		}
	}
}

func getUserProperty(username, property string) string {
	if output, err := shared.RunCommand("dscl", ".", "read", usersDir+username, property); err == nil {
		return parseDarwinProperty(output)
	}
	return ""
}
