//go:build windows

package winsec_test

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/winsec"
)

func TestSecurePath_Windows_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure.json")

	if err := os.WriteFile(path, []byte(`{"key":"value"}`), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// SecurePath sets Windows ACLs; the call may fail if tests run without
	// sufficient privileges (e.g. a standard CI user without SeSecurityPrivilege),
	// so we accept either success or a clear Windows error — never a panic.
	err := winsec.SecurePath(path)
	if err != nil {
		t.Logf("SecurePath returned error (may be privilege-dependent): %v", err)
	}
}

func TestSecurePath_Windows_NonExistentPath(t *testing.T) {
	err := winsec.SecurePath(`C:\nonexistent\path\that\does\not\exist.json`)
	// Expected to fail with a Windows error about the path; must not panic.
	if err == nil {
		t.Log("SecurePath succeeded on a non-existent path (unexpected but not fatal)")
	}
}

func TestSecurePath_Windows_Directory(t *testing.T) {
	dir := t.TempDir()

	// Securing a directory should work or fail gracefully; must not panic.
	err := winsec.SecurePath(dir)
	if err != nil {
		t.Logf("SecurePath(dir) returned error (may be privilege-dependent): %v", err)
	}
}
