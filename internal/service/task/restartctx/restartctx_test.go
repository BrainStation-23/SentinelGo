package restartctx_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/service/task/restartctx"
)

func TestPathFor(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		wantBase   string // we only assert the filename, avoiding OS-specific separators
	}{
		{
			name:       "deep path",
			configPath: filepath.Join("opt", "sentinelgo", ".sentinelgo", "config.json"),
			wantBase:   "pending_restart.json",
		},
		{
			name:       "basename only",
			configPath: "config.json",
			wantBase:   "pending_restart.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := restartctx.PathFor(tt.configPath)
			if filepath.Base(got) != tt.wantBase {
				t.Errorf("PathFor(%q) base = %q, want %q", tt.configPath, filepath.Base(got), tt.wantBase)
			}
			if filepath.Dir(got) != filepath.Dir(tt.configPath) {
				t.Errorf("PathFor(%q) dir = %q, want %q", tt.configPath, filepath.Dir(got), filepath.Dir(tt.configPath))
			}
		})
	}
}

func TestPathFor_SameDirectoryAsConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	got := restartctx.PathFor(configPath)
	if filepath.Dir(got) != dir {
		t.Errorf("PathFor should return a path in the same directory as config: got dir %q, want %q", filepath.Dir(got), dir)
	}
	if filepath.Base(got) != "pending_restart.json" {
		t.Errorf("PathFor should return pending_restart.json as filename, got %q", filepath.Base(got))
	}
}

func TestWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	rc := restartctx.Context{
		TaskID:      "task-abc-123",
		Reason:      "agent-update",
		FromVersion: "v1.2.3",
		InitiatedAt: time.Date(2025, 6, 1, 10, 30, 0, 0, time.UTC),
	}

	if err := restartctx.Write(path, rc); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := restartctx.ReadAndClear(path)
	if err != nil {
		t.Fatalf("ReadAndClear: %v", err)
	}
	if got == nil {
		t.Fatal("ReadAndClear returned nil for existing file")
		return // Early return to satisfy staticcheck
	}
	if got.TaskID != rc.TaskID {
		t.Errorf("TaskID: got %q, want %q", got.TaskID, rc.TaskID)
	}
	if got.Reason != rc.Reason {
		t.Errorf("Reason: got %q, want %q", got.Reason, rc.Reason)
	}
	if got.FromVersion != rc.FromVersion {
		t.Errorf("FromVersion: got %q, want %q", got.FromVersion, rc.FromVersion)
	}
	if !got.InitiatedAt.Equal(rc.InitiatedAt) {
		t.Errorf("InitiatedAt: got %v, want %v", got.InitiatedAt, rc.InitiatedAt)
	}
}

func TestWrite_CreatesFileWithRestrictedPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission check skipped when running as root")
	}
	// Windows does not honour Unix-style mode bits; skip there.
	if os.PathSeparator == '\\' {
		t.Skip("file permission check not applicable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	rc := restartctx.Context{TaskID: "perm-test"}

	if err := restartctx.Write(path, rc); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// On non-Windows the file should be 0600.
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestWrite_NoTempFileAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	tmp := path + ".tmp"

	if err := restartctx.Write(path, restartctx.Context{TaskID: "atomic"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error(".tmp file should not remain after a successful Write")
	}
}

func TestWrite_FailsAndCleansTempFile_WhenDirAbsent(t *testing.T) {
	// Path inside a non-existent subdirectory → rename fails → .tmp must be removed.
	path := filepath.Join(t.TempDir(), "nodir", "pending_restart.json")

	err := restartctx.Write(path, restartctx.Context{TaskID: "err-test"})
	if err == nil {
		t.Fatal("expected error writing to non-existent directory")
	}

	if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
		t.Error(".tmp file should be cleaned up after rename failure")
	}
}

func TestReadAndClear_FileNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.json")
	rc, err := restartctx.ReadAndClear(path)
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if rc != nil {
		t.Fatalf("expected nil context for missing file, got: %+v", rc)
	}
}

func TestReadAndClear_DeletesFileAfterRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	if err := restartctx.Write(path, restartctx.Context{TaskID: "del-me", Reason: "device-reboot"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := restartctx.ReadAndClear(path); err != nil {
		t.Fatalf("ReadAndClear: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted after ReadAndClear")
	}
}

func TestReadAndClear_CorruptJSON_StillDeletesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	rc, err := restartctx.ReadAndClear(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
	if rc != nil {
		t.Fatalf("expected nil context for corrupt JSON, got: %+v", rc)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("file should be deleted even when JSON parse fails")
	}
}

func TestReadAndClear_EmptyJSON_StillDeletesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := restartctx.ReadAndClear(path)
	if err == nil {
		t.Fatal("expected error for empty JSON")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("file should be deleted even when empty")
	}
}

func TestWrite_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pending_restart.json")

	rc1 := restartctx.Context{TaskID: "first", Reason: "agent-update"}
	rc2 := restartctx.Context{TaskID: "second", Reason: "device-reboot"}

	if err := restartctx.Write(path, rc1); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := restartctx.Write(path, rc2); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	got, err := restartctx.ReadAndClear(path)
	if err != nil {
		t.Fatalf("ReadAndClear: %v", err)
	}
	if got.TaskID != rc2.TaskID {
		t.Errorf("second Write should overwrite first: got %q, want %q", got.TaskID, rc2.TaskID)
	}
}
