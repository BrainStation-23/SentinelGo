package walk

import "golang.org/x/sys/unix"

// LowerSelf puts the calling process in the Darwin background band:
// lowest CPU priority, throttled disk and network IO (what `taskpolicy -b`
// does). Scan workers call it at startup (#412).
func LowerSelf() error {
	return unix.Setpriority(unix.PRIO_DARWIN_PROCESS, 0, unix.PRIO_DARWIN_BG)
}
