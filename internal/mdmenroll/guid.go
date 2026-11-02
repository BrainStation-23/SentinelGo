package mdmenroll

import "strings"

// validEnrollmentID accepts a GUID (with or without braces), so nothing
// else reaches a command line.
func validEnrollmentID(id string) bool {
	id = strings.Trim(id, "{}")
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'):
		default:
			return false
		}
	}
	return true
}
