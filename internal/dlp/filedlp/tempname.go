package filedlp

import "strings"

// isTempName reports whether a file name looks like a save's temp file.
func isTempName(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, ".~lock."):
		return false // LibreOffice's lock file: never renamed
	case strings.HasSuffix(lower, ".tmp"), // LibreOffice lu*.tmp, Office ~WRL*.tmp, many others
		strings.HasPrefix(name, "~$"),
		strings.HasPrefix(name, ".goutputstream-"): // GIO's g_file_replace
		return true
	}
	return isHex8(name) // Excel writes its new copy under 8 hex digits
}

func isHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20 // lower case for letters; digits are unchanged
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
