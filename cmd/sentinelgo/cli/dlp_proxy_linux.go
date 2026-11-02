package cli

import (
	"os"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// newProxyScanner scans in the sandboxed workers when run as root, as the
// service does; otherwise in this process.
func newProxyScanner(c *policy.Compiled, bundle []byte, spill string) (filedlp.Scanner, func(), string) {
	if os.Geteuid() != 0 {
		return inProcessScanner(c, spill), func() {}, "not root: files are scanned in this process, not in sandboxed workers"
	}
	exe, err := os.Executable()
	if err != nil {
		return inProcessScanner(c, spill), func() {}, "no executable path: files are scanned in this process"
	}
	pool := scanworker.NewPool(scanworker.Options{Exe: exe})
	pool.SetPolicy(bundle)
	return pool, pool.Stop, ""
}
