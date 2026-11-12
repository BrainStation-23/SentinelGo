//go:build !windows

package report

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ownerID returns the file's owner uid (without following a link).
func ownerID(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Uid), 10), true
}

// ownerName looks the uid up. Without cgo, os/user reads /etc/passwd, so
// directory accounts (macOS Open Directory, LDAP) come back empty.
func ownerName(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return ""
	}
	return u.Username
}
