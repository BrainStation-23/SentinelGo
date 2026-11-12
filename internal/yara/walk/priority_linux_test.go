package walk

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// checkLowered reads the nice value back from /proc and the IO class from
// ioprio_get.
func checkLowered() error {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return err
	}
	s := string(data)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	// After the command: state is field 3, nice is field 19.
	if len(fields) < 17 || fields[16] != "19" {
		return fmt.Errorf("nice = %v, want 19", fields)
	}
	r, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(unix.Gettid()), 0) // #nosec G115 -- tid is positive
	if errno != 0 {
		return errno
	}
	if class := r >> ioprioClassShift; class != ioprioClassIdle {
		return fmt.Errorf("IO class = %d, want idle", class)
	}
	return nil
}
