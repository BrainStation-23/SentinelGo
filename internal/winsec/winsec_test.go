//go:build !windows

package winsec_test

// Tests for the non-Windows stub implementation of SecurePath.
// The stub is compiled on all non-Windows platforms and should be a no-op.

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/winsec"
)

func TestSecurePath_NoopOnNonWindows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// On non-Windows, SecurePath is a documented no-op and must return nil.
	if err := winsec.SecurePath(path); err != nil {
		t.Errorf("SecurePath on non-Windows: expected nil error, got: %v", err)
	}
}

func TestSecurePath_NonExistentPath_NoError(t *testing.T) {
	// The stub ignores the path entirely, so even a non-existent path returns nil.
	if err := winsec.SecurePath("/nonexistent/path/file.json"); err != nil {
		t.Errorf("SecurePath(nonexistent) on non-Windows: expected nil, got: %v", err)
	}
}

func TestSecurePath_EmptyPath_NoError(t *testing.T) {
	if err := winsec.SecurePath(""); err != nil {
		t.Errorf("SecurePath(\"\") on non-Windows: expected nil, got: %v", err)
	}
}

func TestSecurePath_DirectoryPath_NoError(t *testing.T) {
	dir := t.TempDir()
	if err := winsec.SecurePath(dir); err != nil {
		t.Errorf("SecurePath(dir) on non-Windows: expected nil, got: %v", err)
	}
}
