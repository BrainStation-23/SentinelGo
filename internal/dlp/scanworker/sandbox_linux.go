package scanworker

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Worker resource limits. The address-space limit is a backstop for the Go
// memory limit, set well above it because the runtime reserves address space
// it doesn't use.
const (
	workerMemoryLimit = 1 << 30
	workerAddrSpace   = 8 << 30
	workerOpenFiles   = 64
)

// landlockAttr is the start of struct landlock_ruleset_attr. Kernels accept a
// longer struct than they know as long as the tail is zero, so this works on
// every Landlock ABI.
type landlockAttr struct {
	handledFS  uint64
	handledNet uint64
}

// sandbox restricts the worker before it reads anything and describes what
// it applied. no_new_privs and Landlock normally apply to one thread; Go
// already runs several, so both go through AllThreadsSyscall (available
// because the agent is built without cgo). Failing to set no_new_privs or a
// limit is fatal; a kernel without Landlock is not (it is reported).
func sandbox() (string, error) {
	applied := []string{}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return "", fmt.Errorf("no_new_privs: %w", e)
	}
	applied = append(applied, "no_new_privs")

	for _, l := range []struct {
		res int
		max uint64
	}{
		{unix.RLIMIT_FSIZE, 0}, // no file writes
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_NOFILE, workerOpenFiles},
		{unix.RLIMIT_AS, workerAddrSpace},
	} {
		if err := unix.Setrlimit(l.res, &unix.Rlimit{Cur: l.max, Max: l.max}); err != nil {
			return "", fmt.Errorf("rlimit %d: %w", l.res, err)
		}
	}
	debug.SetMemoryLimit(workerMemoryLimit)
	applied = append(applied, "rlimits")

	switch abi, err := landlock(); {
	case err == nil:
		applied = append(applied, fmt.Sprintf("landlock_v%d", abi))
	case errors.Is(err, errNoLandlock):
		applied = append(applied, "no_landlock")
	default:
		return "", err
	}
	return strings.Join(applied, ","), nil
}

var errNoLandlock = errors.New("landlock not available")

// landlock denies every filesystem access by path (and, from ABI 4, TCP)
// with an empty ruleset. Descriptors already open, or received later, keep
// working: Landlock checks at open time.
func landlock() (int, error) {
	r, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		if e == unix.ENOSYS || e == unix.EOPNOTSUPP {
			return 0, errNoLandlock
		}
		return 0, fmt.Errorf("landlock version: %w", e)
	}
	abi := int(r)                                  // #nosec G115 -- a small ABI number
	attr := landlockAttr{handledFS: (1 << 13) - 1} // ABI 1: execute .. make_sym
	if abi >= 2 {
		attr.handledFS |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		attr.handledFS |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 4 {
		attr.handledNet = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	if abi >= 5 {
		attr.handledFS |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) // #nosec G103 -- the kernel ABI takes a struct pointer
	if e != 0 {
		return 0, fmt.Errorf("landlock ruleset: %w", e)
	}
	defer func() { _ = unix.Close(int(fd)) }() // #nosec G115 -- a descriptor
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return 0, fmt.Errorf("landlock restrict: %w", e)
	}
	return abi, nil
}
