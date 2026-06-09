package users

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getLocalUsers() []shared.UserWithGroup {
	output, err := shared.RunCommand("dscl", ".", "list", "/Users")
	if err != nil {
		return nil
	}

	var result []shared.UserWithGroup
	for _, username := range parseDarwinUserList(output) {
		homeOut, err := shared.RunCommand("dscl", ".", "read", "/Users/"+username, "NFSHomeDirectory")
		if err != nil || !strings.Contains(homeOut, "/Users/") {
			continue
		}

		var groups []string
		if groupOut, err := shared.RunCommand("id", "-Gn", username); err == nil {
			groups = parseDarwinIDGroups(groupOut)
		}

		result = append(result, shared.UserWithGroup{
			Username: username,
			Groups:   groups,
			UID:      getUserProperty(username, "UniqueID"),
			GID:      getUserProperty(username, "PrimaryGroupID"),
			HomeDir:  parseDarwinProperty(homeOut),
			Shell:    getUserProperty(username, "UserShell"),
		})
	}
	return result
}

func getUserProperty(username, property string) string {
	if output, err := shared.RunCommand("dscl", ".", "read", "/Users/"+username, property); err == nil {
		return parseDarwinProperty(output)
	}
	return ""
}
