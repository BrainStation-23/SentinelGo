//go:build darwin

package epm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// consoleDevice is owned by the user currently logged into the physical
// console (root when nobody is logged in, e.g. at the login window or on a
// headless Mac) — the traditional, long-standing macOS convention for
// console-user detection, maintained by loginwindow.
const consoleDevice = "/dev/console"

// ConsoleUser returns the UID and username of the user currently logged into
// the physical console. The UID comes from a plain stat(2) syscall (always
// reliable, no name-service resolution involved); the username is resolved
// via the `stat` CLI's own %Su formatter rather than a Go-side /etc/passwd
// parse, because macOS accounts are commonly backed by Open Directory rather
// than /etc/passwd and the OS's own tools resolve that correctly without
// requiring cgo bindings to Directory Services (see CLAUDE.md's no-cgo
// rule — shelling out to the OS's own CLI is the sanctioned alternative).
func ConsoleUser() (uid uint32, username string, err error) {
	info, statErr := os.Stat(consoleDevice)
	if statErr != nil {
		return 0, "", fmt.Errorf("stat %s: %w", consoleDevice, statErr)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, "", fmt.Errorf("unexpected stat info type for %s", consoleDevice)
	}
	uid = st.Uid
	if uid == 0 {
		return 0, "", fmt.Errorf("no user currently logged into the console")
	}

	out, err := exec.Command("stat", "-f", "%Su", consoleDevice).Output()
	if err != nil {
		return uid, "", fmt.Errorf("resolve console username: %w", err)
	}
	username = strings.TrimSpace(string(out))
	if username == "" {
		return uid, "", fmt.Errorf("stat returned an empty console username")
	}
	return uid, username, nil
}
