package users

import (
	"fmt"

	"sentinelgo/internal/osinfo/shared"
)

func getLocalUsers() []shared.UserWithGroup {
	output, err := shared.RunPowerShell(
		`Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name,SID | ConvertTo-Json`)
	if err != nil {
		return nil
	}

	rawUsers := parseWindowsUsersJSON(output)
	for i := range rawUsers {
		rawUsers[i].Groups = getUserGroups(rawUsers[i].Username)
	}
	applyWindowsUserExtras(rawUsers)
	return rawUsers
}

// userExtrasScript lists each local account's enabled flag, last logon and
// password-last-set time (#172). Times are Unix seconds, so neither the
// culture's date format nor its calendar can change them; a null LastLogon
// means the account has never logged on.
const userExtrasScript = `$ts = { param($d) if ($d) { ([DateTimeOffset]$d).ToUnixTimeSeconds() } else { $null } }; ` +
	`$list = Get-LocalUser | ForEach-Object { [pscustomobject]@{ SID = $_.SID.Value; Enabled = [bool]$_.Enabled; LastLogon = (& $ts $_.LastLogon); PasswordLastSet = (& $ts $_.PasswordLastSet) } }; ` +
	`ConvertTo-Json -InputObject @($list) -Compress`

// applyWindowsUserExtras adds is_enabled, last_logon and password_last_set
// from Get-LocalUser, matched by SID. If the query fails the keys are left
// out.
func applyWindowsUserExtras(users []shared.UserWithGroup) {
	out, err := shared.RunPowerShell(userExtrasScript)
	if err != nil {
		return
	}
	extras := parseWindowsUserExtrasJSON(out)
	for i := range users {
		if e, ok := extras[users[i].UID]; ok {
			users[i].IsEnabled = e.Enabled
			users[i].LastLogon = e.LastLogon
			users[i].PasswordLastSet = e.PasswordLastSet
		}
	}
}

// getUserGroups returns the local groups that username belongs to.
// The original `Get-LocalUser | Get-LocalGroup` pipeline is invalid PowerShell;
// this implementation iterates all local groups and tests membership instead.
func getUserGroups(username string) []string {
	cmd := fmt.Sprintf(
		`$u=%s; Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).Name -like ('*\'+$u) } | Select-Object -ExpandProperty Name`,
		shared.PSQuote(username))
	if output, err := shared.RunPowerShell(cmd); err == nil {
		return parseWindowsGroupLines(output)
	}
	return nil
}
