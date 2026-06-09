package users

import (
	"fmt"

	"sentinelgo/internal/osinfo/shared"
)

func getLocalUsers() []shared.UserWithGroup {
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		`Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name,SID | ConvertTo-Json`)
	if err != nil {
		return nil
	}

	rawUsers := parseWindowsUsersJSON(output)
	for i := range rawUsers {
		rawUsers[i].Groups = getUserGroups(rawUsers[i].Username)
	}
	return rawUsers
}

// getUserGroups returns the local groups that username belongs to.
// The original `Get-LocalUser | Get-LocalGroup` pipeline is invalid PowerShell;
// this implementation iterates all local groups and tests membership instead.
func getUserGroups(username string) []string {
	cmd := fmt.Sprintf(
		`$u="%s"; Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).Name -like ('*\'+$u) } | Select-Object -ExpandProperty Name`,
		username)
	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command", cmd); err == nil {
		return parseWindowsGroupLines(output)
	}
	return nil
}
