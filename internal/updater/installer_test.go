package updater

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ── test seam helpers ─────────────────────────────────────────────────────────

// fakeExecutable writes content to a file in a fresh temp dir and points
// executablePath at it, so install/backup/rollback/staging never touch the
// real test binary or anything next to it. It returns the fake binary's path.
func fakeExecutable(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentinelgo-test-bin")
	// #nosec G306 - test fixture standing in for an executable
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatalf("write fake executable: %v", err)
	}
	setExecutablePath(t, func() (string, error) { return path, nil })
	return path
}

func setExecutablePath(t *testing.T, fn func() (string, error)) {
	t.Helper()
	prev := executablePath
	executablePath = fn
	t.Cleanup(func() { executablePath = prev })
}

var errNoExecutable = errors.New("executable path unavailable")

func failExecutablePath(t *testing.T) {
	t.Helper()
	setExecutablePath(t, func() (string, error) { return "", errNoExecutable })
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 - test temp file
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func assertNotExist(t *testing.T, path, what string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s should not exist at %s (stat err = %v)", what, path, err)
	}
}

// blockPath creates a non-empty directory at path, so creating a file there
// or renaming a file over it fails on every OS.
func blockPath(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

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

func TestCreateBackup_CopiesSelf(t *testing.T) {
	content := []byte("current agent binary")
	self := fakeExecutable(t, content)

	backupPath, err := createBackup()
	if err != nil {
		t.Fatalf("createBackup() error: %v", err)
	}
	if backupPath != self+".backup" {
		t.Errorf("backupPath = %q, want %q", backupPath, self+".backup")
	}
	if got := mustReadFile(t, backupPath); !bytes.Equal(got, content) {
		t.Errorf("backup content = %q, want %q", got, content)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatalf("stat backup: %v", err)
		}
		if info.Mode().Perm() != 0755 {
			t.Errorf("backup mode = %v, want 0755 (copied from self)", info.Mode().Perm())
		}
	}
}

func TestCreateBackup_ExecutablePathError(t *testing.T) {
	failExecutablePath(t)
	if _, err := createBackup(); !errors.Is(err, errNoExecutable) {
		t.Errorf("createBackup() error = %v, want %v", err, errNoExecutable)
	}
}

func TestCreateBackup_SelfMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	setExecutablePath(t, func() (string, error) { return missing, nil })

	if _, err := createBackup(); err == nil {
		t.Fatal("expected error when the running binary cannot be opened")
	}
	assertNotExist(t, missing+".backup", "backup")
}

func TestCreateBackup_BackupNotWritable(t *testing.T) {
	self := fakeExecutable(t, []byte("bin"))
	blockPath(t, self+".backup")

	if _, err := createBackup(); err == nil {
		t.Error("expected error when the backup file cannot be created")
	}
}

// A read error mid-copy must not leave a truncated backup behind (a later
// rollback would restore a corrupt binary). Opening a directory succeeds but
// reading it fails, which drives the io.Copy error path.
// Regression test for #115: on Windows the partial backup can only be removed
// once its handle is closed.
func TestCreateBackup_CopyErrorRemovesPartialBackup(t *testing.T) {
	self := t.TempDir()
	setExecutablePath(t, func() (string, error) { return self, nil })

	if _, err := createBackup(); err == nil {
		t.Fatal("expected error when the running binary cannot be read")
	}
	assertNotExist(t, self+".backup", "partial backup")
}

// ── atomicReplace ─────────────────────────────────────────────────────────────

func TestAtomicReplace_ReplacesSelf(t *testing.T) {
	self := fakeExecutable(t, []byte("old binary"))
	newPath := filepath.Join(t.TempDir(), "staged.new")
	newContent := []byte("new binary")
	if err := os.WriteFile(newPath, newContent, 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicReplace(newPath); err != nil {
		t.Fatalf("atomicReplace() error: %v", err)
	}
	if got := mustReadFile(t, self); !bytes.Equal(got, newContent) {
		t.Errorf("self content = %q, want %q", got, newContent)
	}
	assertNotExist(t, newPath, "staged binary")
	assertNotExist(t, filepath.Join(filepath.Dir(self), ".sentinelgo_update_tmp"), "temp file")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(self)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0755 {
			t.Errorf("self mode = %v, want 0755", info.Mode().Perm())
		}
	}
}

func TestAtomicReplace_ExecutablePathError(t *testing.T) {
	failExecutablePath(t)
	if err := atomicReplace("unused"); !errors.Is(err, errNoExecutable) {
		t.Errorf("atomicReplace() error = %v, want %v", err, errNoExecutable)
	}
}

func TestAtomicReplace_StagedFileMissing(t *testing.T) {
	old := []byte("old binary")
	self := fakeExecutable(t, old)

	if err := atomicReplace(filepath.Join(t.TempDir(), "missing.new")); err == nil {
		t.Fatal("expected error when the staged binary is missing")
	}
	if got := mustReadFile(t, self); !bytes.Equal(got, old) {
		t.Errorf("self must be untouched on failure, got %q", got)
	}
}

func TestAtomicReplace_RenameFailureCleansTemp(t *testing.T) {
	// The "running binary" is a non-empty directory, so renaming the temp
	// file over it fails on every OS.
	self := filepath.Join(t.TempDir(), "sentinelgo-test-bin")
	blockPath(t, self)
	setExecutablePath(t, func() (string, error) { return self, nil })

	newPath := filepath.Join(t.TempDir(), "staged.new")
	if err := os.WriteFile(newPath, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicReplace(newPath); err == nil {
		t.Fatal("expected error when the rename fails")
	}
	assertNotExist(t, filepath.Join(filepath.Dir(self), ".sentinelgo_update_tmp"), "temp file")
	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("staged binary should be kept after a failed rename: %v", err)
	}
}

// ── rollbackFromBackup ────────────────────────────────────────────────────────

func TestRollbackFromBackup_ExecutablePathError(t *testing.T) {
	failExecutablePath(t)
	if err := rollbackFromBackup("unused"); !errors.Is(err, errNoExecutable) {
		t.Errorf("rollbackFromBackup() error = %v, want %v", err, errNoExecutable)
	}
}

// On Unix the backup is restored over the binary; on Windows in-process
// rollback is refused (the running .exe is locked) and the backup is kept.
func TestRollbackFromBackup_RestoresBackup(t *testing.T) {
	self := fakeExecutable(t, []byte("broken new binary"))
	backup := self + ".backup"
	good := []byte("known-good binary")
	if err := os.WriteFile(backup, good, 0755); err != nil {
		t.Fatal(err)
	}

	err := rollbackFromBackup(backup)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("expected in-process rollback to be refused on Windows")
		}
		if _, statErr := os.Stat(backup); statErr != nil {
			t.Errorf("backup must be preserved on Windows: %v", statErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("rollbackFromBackup() error: %v", err)
	}
	if got := mustReadFile(t, self); !bytes.Equal(got, good) {
		t.Errorf("self content = %q, want %q", got, good)
	}
	assertNotExist(t, self+".rollback", "rollback temp")
}

func TestRollbackFromBackup_NonExistentBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rollbackFromBackup returns early on Windows before reading the backup")
	}
	fakeExecutable(t, []byte("bin"))
	if err := rollbackFromBackup(filepath.Join(t.TempDir(), "missing.backup")); err == nil {
		t.Error("expected error for nonexistent backup file, got nil")
	}
}

func TestRollbackFromBackup_RenameFailureCleansTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rollbackFromBackup returns before any file I/O on Windows")
	}
	self := filepath.Join(t.TempDir(), "sentinelgo-test-bin")
	blockPath(t, self)
	setExecutablePath(t, func() (string, error) { return self, nil })

	backup := filepath.Join(t.TempDir(), "bin.backup")
	if err := os.WriteFile(backup, []byte("good"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := rollbackFromBackup(backup); err == nil {
		t.Fatal("expected error when the rename fails")
	}
	assertNotExist(t, self+".rollback", "rollback temp")
}
