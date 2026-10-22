package users

import (
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func getIdentity() shared.UserIdentity {
	var id shared.UserIdentity

	id.AdminMembers = linuxAdminRoster()

	if bin, err := lookupBinary("who"); err == nil {
		// The C locale fixes who's date format.
		if out, err := runCommand("env", "LC_ALL=C", bin); err == nil {
			id.SignedInUsers = parseWho(out, time.Now())
		}
	}

	if out, err := runCommand("last", "-w", "-n", "20"); err == nil {
		id.LastSignedInUser = parseLastUser(out)
	}

	if out, err := runCommand("realm", "list"); err == nil {
		id.Join = parseRealmList(out)
	}
	return id
}

// linuxAdminRoster lists the admin groups' members, nil when the account
// records can't be read. getent also sees directory accounts and groups
// (sssd, winbind), so a directory user whose primary group is sudo counts
// too; /etc/passwd says which accounts are local.
func linuxAdminRoster() []shared.LocalAdminMember {
	passwd, err := readFile("/etc/passwd")
	if err != nil {
		return nil
	}
	localUsers := map[string]bool{}
	for name := range parsePasswdGIDs(passwd) {
		localUsers[name] = true
	}
	accounts := passwd
	if out, err := runCommand("getent", "passwd"); err == nil && out != "" {
		accounts = out
	}
	// getent exits 2 when one of the groups doesn't exist, so the output
	// counts, not the exit code.
	groups, _, err := runCommandOutput("getent", append([]string{"group"}, linuxAdminGroups...)...)
	if err != nil || groups == "" {
		if groups, err = readFile("/etc/group"); err != nil {
			return nil
		}
	}
	return linuxAdminMembers(groups, parsePasswdGIDs(accounts), localUsers)
}
