package users

import (
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func getIdentity() shared.UserIdentity {
	var id shared.UserIdentity

	if out, err := shared.RunCommand("dscl", ".", "read", "/Groups/admin", "GroupMembership"); err == nil {
		if names, ok := parseDarwinGroupMembership(out); ok {
			id.AdminMembers = darwinAdminMembers(names, darwinLocalUserNames())
		}
	}

	if out, err := shared.RunCommand("who"); err == nil {
		id.SignedInUsers = parseWho(out, time.Now())
		if owner, err := shared.RunCommand("stat", "-f", "%Su", "/dev/console"); err == nil {
			id.SignedInUsers = addConsoleOwner(id.SignedInUsers, owner)
		}
	}

	if out, err := shared.RunCommand("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "lastUserName"); err == nil {
		id.LastSignedInUser = strings.TrimSpace(out)
	}

	if out, err := shared.RunCommand("dsconfigad", "-show"); err == nil {
		id.Join = parseDsconfigad(out)
	}
	return id
}

// darwinLocalUserNames lists every record under /Users in the local
// directory, system accounts included.
func darwinLocalUserNames() map[string]bool {
	names := map[string]bool{}
	if out, err := shared.RunCommand("dscl", ".", "list", "/Users"); err == nil {
		for _, n := range strings.Fields(out) {
			names[n] = true
		}
	}
	return names
}

// darwinLastLogon reads the user's newest sign-in from the login records
// (`last`). Nil when there's no record.
func darwinLastLogon(user string) *shared.LastLogon {
	out, err := shared.RunCommand("last", "-1", user)
	if err != nil {
		return nil
	}
	if t, ok := parseDarwinLastLogon(out, user, time.Now()); ok {
		return shared.LoggedOnAt(t)
	}
	return nil
}
