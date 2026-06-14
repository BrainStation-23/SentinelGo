package updater

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ── copyFile ──────────────────────────────────────────────────────────────────

func TestCopyFile_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	dst := filepath.Join(dir, "dest.bin")

	content := []byte("sentinel binary content")
	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("destination content = %q, want %q", got, content)
	}
}

func TestCopyFile_SourceMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nonexistent.bin")
	dst := filepath.Join(dir, "dest.bin")

	if err := copyFile(src, dst); err == nil {
		t.Error("expected error when source file is missing, got nil")
	}
}

func TestCopyFile_DestDirMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	dst := filepath.Join(dir, "nonexistent_dir", "dest.bin")

	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := copyFile(src, dst); err == nil {
		t.Error("expected error when destination directory is missing, got nil")
	}
}

// ── removeFile ────────────────────────────────────────────────────────────────

func TestRemoveFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "to_delete.bin")

	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := removeFile(path); err != nil {
		t.Fatalf("removeFile() error: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed")
	}
}

func TestRemoveFile_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.bin")

	// os.Remove on a non-existent file returns an error
	if err := removeFile(path); err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// ── createBackup ──────────────────────────────────────────────────────────────

func TestCreateBackup_CreatesBackupFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, creating/removing a .backup next to a test binary under
		// a locked path can fail. Skip gracefully.
		t.Skip("skipping createBackup on Windows CI")
	}

	backupPath, err := createBackup()
	if err != nil {
		// createBackup calls os.Executable() + file I/O. If permissions prevent
		// writing next to the test binary, skip rather than fail.
		t.Skipf("createBackup() not possible in this environment: %v", err)
	}

	// Verify backup file exists
	if _, statErr := os.Stat(backupPath); statErr != nil {
		t.Errorf("backup file not found at %s: %v", backupPath, statErr)
	}

	// Clean up — best effort
	_ = os.Remove(backupPath)
}

func TestCreateBackup_BackupHasContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping createBackup on Windows CI")
	}

	backupPath, err := createBackup()
	if err != nil {
		t.Skipf("createBackup() not possible in this environment: %v", err)
	}
	defer func() { _ = os.Remove(backupPath) }()

	selfPath, _ := os.Executable()
	selfInfo, err := os.Stat(selfPath)
	if err != nil {
		t.Fatalf("stat self: %v", err)
	}
	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}

	if backupInfo.Size() != selfInfo.Size() {
		t.Errorf("backup size = %d, want %d (same as self)", backupInfo.Size(), selfInfo.Size())
	}
}

// ── rollbackFromBackup ────────────────────────────────────────────────────────

// TestRollbackFromBackup_Windows verifies that on Windows, rollback always returns
// an error (in-process file replacement is not supported while the binary is running).
func TestRollbackFromBackup_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific path only")
	}
	err := rollbackFromBackup("any_backup.backup")
	if err == nil {
		t.Error("expected error from rollbackFromBackup on Windows, got nil")
	}
}

// TestRollbackFromBackup_NonExistentBackup verifies that passing a nonexistent
// backup path returns an error on non-Windows platforms.
func TestRollbackFromBackup_NonExistentBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rollbackFromBackup returns early on Windows before reading the backup")
	}
	err := rollbackFromBackup("/nonexistent/path/to/backup.backup")
	if err == nil {
		t.Error("expected error for nonexistent backup file, got nil")
	}
}

// TestCreateBackup_ContentMatchesSource verifies that the backup file's bytes are
// identical to the source binary, not merely the same size.
func TestCreateBackup_ContentMatchesSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping createBackup on Windows CI")
	}

	backupPath, err := createBackup()
	if err != nil {
		t.Skipf("createBackup() not possible in this environment: %v", err)
	}
	defer func() { _ = os.Remove(backupPath) }()

	selfPath, _ := os.Executable()
	selfBytes, err := os.ReadFile(selfPath)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}

	if len(selfBytes) != len(backupBytes) {
		t.Fatalf("length mismatch: self=%d backup=%d", len(selfBytes), len(backupBytes))
	}
	for i := range selfBytes {
		if selfBytes[i] != backupBytes[i] {
			t.Errorf("content differs at byte %d: self=%02x backup=%02x", i, selfBytes[i], backupBytes[i])
			break
		}
	}
}
