package lockfile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// LockFile represents a process lock file
type LockFile struct {
	path     string
	file     *os.File
	acquired bool
}

// NewLockFile creates a new lock file instance
func NewLockFile(name string) *LockFile {
	var lockDir string
	switch runtime.GOOS {
	case "windows":
		home, err := os.UserHomeDir()
		if err != nil {
			home = "C:\\SentinelGo"
		}
		lockDir = filepath.Join(home, ".sentinelgo")
	case "linux", "darwin":
		lockDir = "/opt/sentinelgo/.sentinelgo"
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		lockDir = filepath.Join(home, ".sentinelgo")
	}

	if err := os.MkdirAll(lockDir, 0750); err != nil {
		// Continue even if we can't create the directory
		// The lock file creation will fail later if needed
		_ = err // Explicitly ignore the error
	}

	return &LockFile{
		path: filepath.Join(lockDir, name+".lock"),
	}
}

// NewLockFileWithPath creates a new lock file instance with a custom path (for testing)
func NewLockFileWithPath(path string) *LockFile {
	return &LockFile{
		path: path,
	}
}

// TryAcquire attempts to acquire the lock
func (lf *LockFile) TryAcquire() error {
	// Check if lock file already exists
	if _, err := os.Stat(lf.path); err == nil {
		// Lock file exists, check if process is still running
		if lf.isProcessRunning() {
			return fmt.Errorf("lock already held by another process")
		}
		// Process is not running, remove stale lock file
		if err := os.Remove(lf.path); err != nil {
			// Log error but continue - file might not exist
			_ = err
		}
	}

	// Try to create lock file with exclusive access
	// #nosec G302 - Lock files need to be readable by other processes to check lock status
	file, err := os.OpenFile(lf.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("lock already held by another process")
		}
		return fmt.Errorf("failed to create lock file: %w", err)
	}
	lf.file = file

	// Write our PID to the lock file
	pid := os.Getpid()
	_, err = file.WriteString(strconv.Itoa(pid) + "\n")
	if err != nil {
		if cerr := file.Close(); cerr != nil {
			// Log error but continue
			_ = cerr
		}
		lf.file = nil
		if rerr := os.Remove(lf.path); rerr != nil {
			// Log error but continue
			_ = rerr
		}
		return fmt.Errorf("write PID: %w", err)
	}

	// Sync to ensure PID is written to disk
	if err := file.Sync(); err != nil {
		if cerr := file.Close(); cerr != nil {
			// Log error but continue
			_ = cerr
		}
		lf.file = nil
		if rerr := os.Remove(lf.path); rerr != nil {
			// Log error but continue
			_ = rerr
		}
		return fmt.Errorf("sync file: %w", err)
	}

	lf.acquired = true
	return nil
}

// AcquireWithTimeout attempts to acquire the lock with a timeout
func (lf *LockFile) AcquireWithTimeout(timeout time.Duration) error {
	start := time.Now()
	for time.Since(start) < timeout {
		err := lf.TryAcquire()
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "lock already held") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout acquiring lock after %v", timeout)
}

// Release releases the lock
func (lf *LockFile) Release() error {
	if !lf.acquired || lf.file == nil {
		return nil
	}

	// Remove the lock file
	if err := os.Remove(lf.path); err != nil {
		// Log error but continue
		_ = err
	}

	// Close the file
	if err := lf.file.Close(); err != nil {
		// Log error but continue
		_ = err
	}
	lf.file = nil
	lf.acquired = false

	return nil
}

// GetLockedPID returns the PID of the process holding the lock
func (lf *LockFile) GetLockedPID() (int, error) {
	data, err := os.ReadFile(lf.path)
	if err != nil {
		return 0, err
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID in lock file: %s", pidStr)
	}

	return pid, nil
}

// IsProcessRunning checks if a process with the given PID is running
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	if runtime.GOOS == "windows" {
		defer func() { _ = process.Release() }()
		// On Windows, Signal(os.Kill) succeeds (nil error) when the process exists.
		return process.Signal(os.Kill) == nil
	}

	// For Unix systems (Linux/macOS), use Signal(0) to check if process exists
	// This is a non-lethal signal that just checks if the process is reachable
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// isProcessRunning checks if the process in the lock file is still running
func (lf *LockFile) isProcessRunning() bool {
	data, err := os.ReadFile(lf.path)
	if err != nil {
		return false
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return false
	}

	return IsProcessRunning(pid)
}

// CheckExistingLock checks if there's an existing lock and if the process is still running
func (lf *LockFile) CheckExistingLock() (bool, error) {
	pid, err := lf.GetLockedPID()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // No lock file exists
		}
		return false, err
	}

	// Check if the process is still running
	if IsProcessRunning(pid) {
		return true, nil // Process is still running
	}

	// Process is dead, clean up the stale lock file
	if err := os.Remove(lf.path); err != nil {
		// Log error but continue
		_ = err
	}
	return false, nil
}
