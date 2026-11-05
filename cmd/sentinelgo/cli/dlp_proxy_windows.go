package cli

import (
	"os"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// newProxyScanner scans in sandboxed workers (a restricted, low-integrity
// token in a Job object, #328), whoever runs the proxy; only when this
// binary's path is unknown does it scan in this process.
func newProxyScanner(c *policy.Compiled, bundle []byte, spill string) (filedlp.Scanner, func(), string) {
	exe, err := os.Executable()
	if err != nil {
		return inProcessScanner(c, spill), func() {}, "no executable path: files are scanned in this process"
	}
	pool := scanworker.NewPool(scanworker.Options{Exe: exe})
	pool.SetPolicy(bundle)
	return pool, pool.Stop, ""
}
