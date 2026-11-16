package walk

import (
	"io/fs"
	"runtime"
	"syscall"
	"testing"

	"sentinelgo/internal/yara"
)

// A file another process holds is "locked" on every OS.
func TestErrorReason_Locked(t *testing.T) {
	var errno syscall.Errno = 32 // ERROR_SHARING_VIOLATION
	if runtime.GOOS != "windows" {
		errno = syscall.EBUSY
	}
	if r := ErrorReason(&fs.PathError{Op: "open", Path: "x", Err: errno}); r != yara.ErrLocked {
		t.Errorf("%v: %q", errno, r)
	}
}
