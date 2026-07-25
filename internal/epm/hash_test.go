package epm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeFileHash_KnownVector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// echo -n "hello world" | sha256sum
	const want = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	got, err := ComputeFileHash(path)
	if err != nil {
		t.Fatalf("ComputeFileHash: %v", err)
	}
	if got != want {
		t.Errorf("ComputeFileHash = %q, want %q", got, want)
	}
}

func TestComputeFileHash_MissingFile(t *testing.T) {
	_, err := ComputeFileHash(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
