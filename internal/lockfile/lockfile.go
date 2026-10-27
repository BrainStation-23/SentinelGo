// Package lockfile is the agent's single-instance guard.
//
// The lock is held by the operating system for as long as the lock file stays
// open: a share-deny handle on Windows, flock(2) on Linux and macOS. The kernel
// drops it when the process exits for any reason (stop, self-update, kill,
// crash, power loss), so a lock can never be stale and PID reuse can't keep the
// agent from starting (#242). The PID written into the file is for humans and
// diagnostics only; nothing reads it back to decide whether an agent is running.
package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ErrAlreadyRunning is returned by TryAcquire when another process holds the
// lock.
var ErrAlreadyRunning = errors.New("another SentinelGo agent is already running")

// LockFile represents a process lock file
type LockFile struct {
	path string
	file *os.File // non-nil while the lock is held
}

// NewLockFile returns the lock <lock dir>/<name>.lock. The lock directory is
// fixed per OS and the same for every account, so a service and a foreground
// run always contend for the same file (see lockDir).
func NewLockFile(name string) *LockFile {
	dir := lockDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		// Continue: TryAcquire reports the real error if the directory is
		// unusable.
		_ = err
	}
	return &LockFile{path: filepath.Join(dir, name+".lock")}
}

// NewLockFileWithPath creates a new lock file instance with a custom path (for testing)
func NewLockFileWithPath(path string) *LockFile {
	return &LockFile{path: path}
}

// Path returns the lock file's path.
func (lf *LockFile) Path() string {
	return lf.path
}

// TryAcquire takes the lock without waiting. It returns ErrAlreadyRunning when
// another process (or another LockFile in this process) holds it, and a
// different error when the file can't be opened at all. Calling it again on a
// LockFile that already holds the lock is a no-op.
//
// An existing file is reused whatever it contains, so a file left behind by an
// earlier run never blocks a start.
func (lf *LockFile) TryAcquire() error {
	if lf.file != nil {
		return nil
	}
	f, err := openLocked(lf.path)
	if err != nil {
		return err
	}
	lf.file = f

	// The PID is informational only. The lock is already held at this point,
	// so failing to record it must not fail the acquire.
	_ = writePID(f)
	return nil
}

func writePID(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return err
	}
	return f.Sync()
}

// Release drops the lock by closing the file. It deliberately leaves the file
// on disk: deleting it would let a process that opened the old file before the
// delete and one that creates a new file both believe they hold the lock.
// Release on a LockFile that doesn't hold the lock is a no-op.
func (lf *LockFile) Release() error {
	if lf.file == nil {
		return nil
	}
	err := lf.file.Close()
	lf.file = nil
	if err != nil {
		return fmt.Errorf("close lock file: %w", err)
	}
	return nil
}
