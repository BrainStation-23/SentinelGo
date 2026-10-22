package users

import (
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func getIdentity() shared.UserIdentity {
	var id shared.UserIdentity

	id.AdminMembers = darwinAdminRoster()

	if out, err := runCommand("who"); err == nil {
		id.SignedInUsers = parseWho(out, time.Now())
		if owner, err := runCommand("stat", "-f", "%Su", "/dev/console"); err == nil {
			id.SignedInUsers = addConsoleOwner(id.SignedInUsers, owner)
		}
	}

	if out, err := runCommand("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "lastUserName"); err == nil {
		id.LastSignedInUser = strings.TrimSpace(out)
	}

	if out, err := runCommand("dsconfigad", "-show"); err == nil {
		id.Join = parseDsconfigad(out)
	}
	return id
}

// darwinAdminRoster lists the admin group's members, nil when either the
// group or the local account list can't be read: without the account list
// a local admin couldn't be told from a directory one.
func darwinAdminRoster() []shared.LocalAdminMember {
	out, err := runCommand("dscl", ".", "read", "/Groups/admin", "GroupMembership")
	if err != nil {
		return nil
	}
	names, ok := parseDarwinGroupMembership(out)
	if !ok {
		return nil
	}
	local, ok := darwinLocalUserNames()
	if !ok {
		return nil
	}
	return darwinAdminMembers(names, local)
}

// darwinLocalUserNames lists every record under /Users in the local
// directory, system accounts included. ok is false when dscl fails.
func darwinLocalUserNames() (map[string]bool, bool) {
	out, err := runCommand("dscl", ".", "list", "/Users")
	if err != nil {
		return nil, false
	}
	names := map[string]bool{}
	for _, n := range strings.Fields(out) {
		names[n] = true
	}
	return names, true
}

// darwinLastLogon reads the user's newest sign-in from the login records
// (`last`). Nil when there's no record.
func darwinLastLogon(user string) *shared.LastLogon {
	out, err := runCommand("last", "-1", user)
	if err != nil {
		return nil
	}
	if t, ok := parseDarwinLastLogon(out, user, time.Now()); ok {
		return shared.LoggedOnAt(t)
	}
	return nil
}
