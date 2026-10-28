package ipc

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// peerCred reads SO_PEERCRED.
func peerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), int(cred.Pid), nil
}

// processExe is the executable of pid, from /proc ("" if unknown). A binary
// replaced by a self-update reads as "<path> (deleted)".
func processExe(pid int) string {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(exe, " (deleted)")
}
