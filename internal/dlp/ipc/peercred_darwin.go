package ipc

import (
	"strings"

	"golang.org/x/sys/unix"
)

// peerCred reads LOCAL_PEERCRED (uid) and LOCAL_PEERPID.
func peerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	pid, err = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), pid, nil
}

// processExe is the executable of pid, from kern.procargs2 ("" if unknown):
// a 4-byte argc, then the NUL-terminated exec path.
func processExe(pid int) string {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buf) < 5 {
		return ""
	}
	path, _, _ := strings.Cut(string(buf[4:]), "\x00")
	return path
}
