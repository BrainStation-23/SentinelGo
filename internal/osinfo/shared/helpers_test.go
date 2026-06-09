package shared_test

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestReadFileContent_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	want := "hello world"
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileContent(path)
	if err != nil {
		t.Fatalf("ReadFileContent() error: %v", err)
	}
	if got != want {
		t.Errorf("ReadFileContent() = %q, want %q", got, want)
	}
}

func TestReadFileContent_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileContent(path)
	if err != nil {
		t.Fatalf("ReadFileContent() on empty file error: %v", err)
	}
	if got != "" {
		t.Errorf("ReadFileContent(empty) = %q, want %q", got, "")
	}
}

func TestReadFileContent_NotFound(t *testing.T) {
	got, err := shared.ReadFileContent(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err == nil {
		t.Error("ReadFileContent() on missing file should return error, got nil")
	}
	if got != "" {
		t.Errorf("ReadFileContent() on missing file = %q, want empty string", got)
	}
}

func TestReadFileBytes_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	want := []byte{0x01, 0x02, 0x03, 0xFF}
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileBytes(path)
	if err != nil {
		t.Fatalf("ReadFileBytes() error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("ReadFileBytes() = %v, want %v", got, want)
	}
}

func TestReadFileBytes_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileBytes(path)
	if err != nil {
		t.Fatalf("ReadFileBytes() on empty file error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadFileBytes(empty) = %v, want empty", got)
	}
}

func TestReadFileBytes_NotFound(t *testing.T) {
	got, err := shared.ReadFileBytes(filepath.Join(t.TempDir(), "nonexistent.bin"))
	if err == nil {
		t.Error("ReadFileBytes() on missing file should return error, got nil")
	}
	if got != nil {
		t.Errorf("ReadFileBytes() on missing file = %v, want nil", got)
	}
}
