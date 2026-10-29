package ipc

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func testAddress(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\sentinelgo-dlp-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}
