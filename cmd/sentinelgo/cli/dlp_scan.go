package cli

import (
	"fmt"
	"os"

	"sentinelgo/internal/dlp/scanworker"
)

// DLPScanCommand is the hidden subcommand the service starts for each file
// DLP scan worker (#328). It takes no flags, reads no config and holds no
// credentials: it sandboxes itself and serves scans on fd 3.
const DLPScanCommand = scanworker.Command

// RunDLPScan runs a scan worker until the service closes its socket. It logs
// nothing about the files it reads.
func RunDLPScan() int {
	if err := scanworker.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "dlp-scan: %v\n", err)
		return 1
	}
	return 0
}
