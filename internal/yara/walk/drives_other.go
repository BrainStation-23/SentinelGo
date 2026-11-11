//go:build !windows

package walk

// fixedDrives is Windows only: a full scan on macOS and Linux has fixed
// roots (fullPaths).
func fixedDrives() []string { return nil }
