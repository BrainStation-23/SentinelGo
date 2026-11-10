package walk

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// ioprio_set(2) values: IOPRIO_WHO_PROCESS targets one thread id, and the
// idle class only gets disk time when nothing else wants it.
const (
	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13
)

// LowerSelf puts the calling process at the lowest CPU and IO priority:
// nice 19 and the idle IO class. Both are per thread on Linux, so every
// thread of the process is changed; threads started later inherit it from
// the thread that creates them. Scan workers call it at startup (#412).
func LowerSelf() error {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	var first error
	for _, t := range tasks {
		tid, err := strconv.Atoi(t.Name())
		if err != nil {
			continue
		}
		if err := unix.Setpriority(unix.PRIO_PROCESS, tid, 19); err != nil && first == nil {
			first = err
		}
		_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift) // #nosec G115 -- tid is a positive thread id
		if errno != 0 && first == nil {
			first = errno
		}
	}
	return first
}
