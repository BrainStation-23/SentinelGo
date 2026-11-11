package cli

import (
	"fmt"
	"os"

	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/yara/walk"
)

// DLPScanCommand is the hidden subcommand the service starts for each file
// DLP scan worker (#328). It takes no flags, reads no config and holds no
// credentials: it sandboxes itself and serves scans on fd 3.
const DLPScanCommand = scanworker.Command

// RunDLPScan runs a scan worker until the service closes its socket. It logs
// nothing about the files it reads.
func RunDLPScan() int {
	if os.Getenv(scanworker.BackgroundEnv) == "1" {
		// Threat hunting workers run in the background (#413); before Serve,
		// whose sandbox may forbid it.
		if err := walk.LowerSelf(); err != nil {
			fmt.Fprintf(os.Stderr, "dlp-scan: could not lower priority: %v\n", err)
		}
	}
	if err := scanworker.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "dlp-scan: %v\n", err)
		return 1
	}
	return 0
}
