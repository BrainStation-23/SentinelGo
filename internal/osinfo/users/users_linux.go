package users

import (
	"sentinelgo/internal/osinfo/shared"
)

func getLocalUsers() []shared.UserWithGroup {
	content, err := shared.ReadFileContent("/etc/passwd")
	if err != nil {
		return nil
	}

	result := parsePasswdContent(content)
	for i := range result {
		if output, err := shared.RunCommand("groups", result[i].Username); err == nil {
			result[i].Groups = parseLinuxGroupOutput(output, result[i].Username)
		}
	}
	return result
}
