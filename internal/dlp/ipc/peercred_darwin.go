package ipc

import "golang.org/x/sys/unix"

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
