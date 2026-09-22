//go:build !windows

package winsec

import "os"

// RunningAsSystem reports whether the process runs as the platform's most
// privileged account. On Unix that is uid 0.
func RunningAsSystem() bool { return os.Geteuid() == 0 }
