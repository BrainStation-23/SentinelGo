//go:build !linux && !windows

package cli

import (
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
)

// newProxyScanner scans in this process: sandboxed workers only run on Linux and Windows.
func newProxyScanner(c *policy.Compiled, _ []byte, spill string) (filedlp.Scanner, func(), string) {
	return inProcessScanner(c, spill), func() {}, "files are scanned in this process (sandboxed workers run on Linux and Windows only)"
}
