package updater

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// executablePath resolves the running binary's path. It is a variable so tests
// can point the install/backup/rollback/staging logic at a file in a temp
// directory instead of the real test binary.
var executablePath = os.Executable

// atomicReplace replaces the running binary with newPath using an atomic rename.
// Not used on Windows (handled via restart batch script).
func atomicReplace(newPath string) error {
	selfPath, err := executablePath()
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

// createBackup copies the running binary to <self>.backup and returns the path.
func createBackup() (string, error) {
	selfPath, err := executablePath()
	if err != nil {
		return "", err
	}

	backupPath := selfPath + ".backup"

	// #nosec G304 - selfPath is a controlled path from executablePath()
	src, err := os.Open(selfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()

	// #nosec G304 - backupPath is a controlled path
	dst, err := os.Create(backupPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to remove backup file %s: %v", backupPath, removeErr)
		}
		return "", err
	}

	if info, err := os.Stat(selfPath); err == nil {
		if err := os.Chmod(backupPath, info.Mode()); err != nil {
			log.Printf("Warning: failed to set permissions on backup: %v", err)
		}
	}

	return backupPath, nil
}

// rollbackFromBackup restores the binary from backupPath using an atomic rename.
func rollbackFromBackup(backupPath string) error {
	selfPath, err := executablePath()
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
