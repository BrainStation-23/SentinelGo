package ipc

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
)

var testPipes atomic.Int64

// testAddress returns a pipe name unique within this run (the clock alone
// can repeat between calls).
func testAddress(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\sentinelgo-dlp-test-%d-%d`, os.Getpid(), testPipes.Add(1))
}
