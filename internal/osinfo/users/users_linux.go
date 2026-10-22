package users

import (
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func getLocalUsers() []shared.UserWithGroup {
	content, err := readFile("/etc/passwd")
	if err != nil {
		return nil
	}

	result := parsePasswdContent(content)
	for i := range result {
		if output, err := runCommand("groups", result[i].Username); err == nil {
			result[i].Groups = parseLinuxGroupOutput(output, result[i].Username)
		}
	}
	applyLinuxAccountState(result)
	return result
}

// applyLinuxAccountState adds is_enabled and password_last_set from
// /etc/shadow (readable as root) and last_logon from lastlog (#172). Each
// is left out when its source can't be read.
func applyLinuxAccountState(users []shared.UserWithGroup) {
	var shadow map[string]shadowEntry
	if content, err := readFile("/etc/shadow"); err == nil {
		shadow = parseShadow(content)
	}
	logons := readLastlog()
	now := time.Now()
	for i := range users {
		if e, ok := shadow[users[i].Username]; ok {
			st := accountStateFromShadow(e, now)
			users[i].IsEnabled = &st.Enabled
			users[i].PasswordLastSet = st.ChangedAt
		}
		users[i].LastLogon = logons[users[i].Username]
	}
}

// readLastlog runs lastlog (or lastlog2, which replaces it on newer
// distributions) in the C locale so the date column has a fixed format. env
// would search PATH for it, so lastlog is passed resolved, and skipped when
// it isn't at its fixed path.
func readLastlog() map[string]*shared.LastLogon {
	for _, cmd := range []string{"lastlog", "lastlog2"} {
		bin, err := lookupBinary(cmd)
		if err != nil {
			continue
		}
		if out, err := runCommand("env", "LC_ALL=C", bin); err == nil {
			return parseLastlog(out)
		}
	}
	return nil
}
