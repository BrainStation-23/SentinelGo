package users

import (
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func getIdentity() shared.UserIdentity {
	var id shared.UserIdentity

	passwd, passwdErr := shared.ReadFileContent("/etc/passwd")
	gids := parsePasswdGIDs(passwd)
	localUsers := map[string]bool{}
	for name := range gids {
		localUsers[name] = true
	}
	// getent also sees groups from a directory (sssd, winbind). It exits 2
	// when one of the groups doesn't exist, so the output counts, not the code.
	groups, _, err := shared.RunCommandOutput("getent", append([]string{"group"}, linuxAdminGroups...)...)
	if err != nil || groups == "" {
		groups, err = shared.ReadFileContent("/etc/group")
	}
	if err == nil && passwdErr == nil {
		id.AdminMembers = linuxAdminMembers(groups, gids, localUsers)
	}

	if bin, err := shared.LookupBinary("who"); err == nil {
		// The C locale fixes who's date format.
		if out, err := shared.RunCommand("env", "LC_ALL=C", bin); err == nil {
			id.SignedInUsers = parseWho(out, time.Now())
		}
	}

	if out, err := shared.RunCommand("last", "-w", "-n", "20"); err == nil {
		id.LastSignedInUser = parseLastUser(out)
	}

	if out, err := shared.RunCommand("realm", "list"); err == nil {
		id.Join = parseRealmList(out)
	}
	return id
}
