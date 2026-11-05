package scanworker

import (
	"fmt"
	"os"
)

// workerFD is the descriptor the worker's socket arrives on.
const workerFD = 3

// Serve is `sentinelgo dlp-scan`: it sandboxes the process, then serves scan
// requests on fd 3 until the service closes the socket. It never opens a path.
func Serve() error {
	desc, err := sandbox()
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	c, _, err := fileConn(os.NewFile(workerFD, "scan-socket"))
	if err != nil {
		return fmt.Errorf("fd %d: %w", workerFD, err)
	}
	return serve(c, desc)
}
