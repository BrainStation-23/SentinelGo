package scanworker

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var (
	exeOnce sync.Once
	exePath string
	exeErr  error
)

// testExe returns the test binary for workers to run. As root the pool runs
// workers as an unprivileged account, which can't reach `go test`'s private
// build directory, so the binary is copied somewhere it can.
func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		return exe
	}
	exeOnce.Do(func() { exePath, exeErr = copyExecutable(exe) })
	if exeErr != nil {
		t.Fatal(exeErr)
	}
	return exePath
}

func copyExecutable(src string) (string, error) {
	dir, err := os.MkdirTemp("", "scanworker-test-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- the unprivileged worker must execute it
		return "", err
	}
	in, err := os.Open(src) // #nosec G304 -- the running test binary
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	dst := filepath.Join(dir, "worker.test")
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G302 G304 -- see above
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", err
	}
	return dst, out.Close()
}
