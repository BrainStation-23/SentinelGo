//go:build !linux && !windows

package scanworker

// Serve is `sentinelgo dlp-scan`; workers run on Linux and Windows.
func Serve() error { return ErrUnsupported }

// RemoveScanAccount has nothing to remove here: workers only run on Linux.
func RemoveScanAccount() error { return nil }
