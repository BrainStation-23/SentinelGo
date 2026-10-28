//go:build linux || darwin

package session

import (
	"os"
	"path/filepath"
	"testing"
)

// testAddress is under /tmp: macOS limits socket paths to 104 bytes, which
// t.TempDir() can exceed.
func testAddress(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dlpipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s", "dlp.sock")
}
