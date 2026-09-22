package updater

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"sentinelgo/internal/paths"
	"sentinelgo/internal/winsec"
)

// atomicReplace replaces the running binary with newPath using an atomic rename.
// Not used on Windows (handled via restart batch script).
func atomicReplace(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	dir := filepath.Dir(selfPath)
	tempPath := filepath.Join(dir, ".sentinelgo_update_tmp")

	if err := copyFile(newPath, tempPath); err != nil {
		return fmt.Errorf("copy to temp file failed: %w", err)
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	_ = os.Remove(newPath)

	// #nosec G302 - Executable binaries need 0755 permissions
	if err := os.Chmod(selfPath, 0755); err != nil {
		return fmt.Errorf("set executable permissions failed: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	// #nosec G304 - src and dst are controlled paths for self-update
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	// #nosec G304 - dst is a controlled path for self-update
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()

	_, err = io.Copy(destination, source)
	return err
}

func removeFile(path string) error {
	return os.Remove(path)
}

// createBackup copies the running binary into the staging directory and returns
// the path.
//
// The copy is a complete, runnable agent binary, so it needs the same protection
// as the binary itself: it previously sat next to the executable with whatever
// permissions it inherited, in a directory a standard user could write, while
// every other update artifact was ACL'd. An attacker-controlled "backup" is a
// straightforward way to get privileged code executed by an operator following
// the rollback instructions.
func createBackup() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	stagingDir := paths.StagingDir()
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	if err := winsec.SecureSystemPath(stagingDir); err != nil {
		return "", fmt.Errorf("refusing to back up: cannot secure staging directory %s: %w",
			stagingDir, err)
	}

	backupPath := filepath.Join(stagingDir, filepath.Base(selfPath)+".backup")

	// #nosec G304 - selfPath is a controlled path from os.Executable()
	src, err := os.Open(selfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()

	// A stale backup from a previous update would make CreateSecureFile fail,
	// since it refuses to adopt an existing file.
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove stale backup %s: %w", backupPath, err)
	}

	dst, err := winsec.CreateSecureFile(backupPath)
	if err != nil {
		return "", fmt.Errorf("create secure backup: %w", err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to remove backup file %s: %v", backupPath, removeErr)
		}
		return "", err
	}

	return backupPath, nil
}

// rollbackFromBackup restores the binary from backupPath using an atomic rename.
func rollbackFromBackup(backupPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("Cannot perform in-process rollback on Windows (file locked).\n")
		fmt.Printf("Backup preserved at: %s\n", backupPath)
		fmt.Printf("To manually restore: copy %s %s\n", backupPath, selfPath)
		return fmt.Errorf("in-process rollback not supported on Windows")
	}

	tempPath := selfPath + ".rollback"
	if err := copyFile(backupPath, tempPath); err != nil {
		return err
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	fmt.Printf("Successfully rolled back from backup: %s\n", backupPath)
	return nil
}

// restart hands control to the OS service manager so the new binary runs.
//
// On Linux/macOS the binary has ALREADY been replaced in place by atomicReplace
// before this is called, so we simply exit and let the service manager relaunch
// the (now-new) binary:
//   - macOS launchd has KeepAlive=true: it relaunches on any exit.
//   - Linux systemd has Restart=on-failure: it relaunches on a non-zero exit.
//
// On Windows a running .exe cannot be replaced in place, so the swap is deferred
// to a small script that waits for this process to exit, moves the new binary
// into place, and starts the service again via the SCM.
//
// The version is intentionally NOT persisted before this point: if the swap or
// relaunch fails, the old binary keeps running and its compiled-in version
// (config.Version) ensures the update is retried on the next check, rather than
// the agent silently reporting a version it isn't running.
func restart(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	return restartPlatform(newPath, selfPath)
}
