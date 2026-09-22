//go:build !windows

package winsec_test

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/winsec"
)

// TestStubsMatchWindowsSurface calls every exported symbol on the non-Windows
// build.
//
// The point is not the assertions; it is that this file fails to compile if the
// Windows and non-Windows builds ever drift apart. Callers use these names
// without build tags, so a signature that exists only on one side would break
// the other platform's build -- and the Windows-only implementation is never
// compiled by the Linux and macOS CI jobs.
func TestStubsMatchWindowsSurface(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := winsec.SecureSystemPath(file); err != nil {
		t.Errorf("SecureSystemPath: %v", err)
	}
	if err := winsec.SecureSystemTree(dir); err != nil {
		t.Errorf("SecureSystemTree: %v", err)
	}
	if err := winsec.SecurePath(file); err != nil {
		t.Errorf("SecurePath: %v", err)
	}
	if err := winsec.VerifyPath(file); err != nil {
		t.Errorf("VerifyPath: %v", err)
	}

	audit, err := winsec.AuditPath(file)
	if err != nil {
		t.Fatalf("AuditPath: %v", err)
	}
	// Unix enforces the same intent with file modes. Reporting a problem here
	// would push callers into the degraded mode reserved for a suspected
	// compromise, disabling updates and task execution on every Linux host.
	if !audit.Secure() {
		t.Errorf("non-Windows AuditPath must report secure, got %q", audit.Reason())
	}
	if _, err := winsec.VerifyFileAndParent(file); err != nil {
		t.Errorf("VerifyFileAndParent: %v", err)
	}

	_ = winsec.Offender{}.String()
}

// TestCreateSecureFile_Other pins the two behaviours the updater depends on:
// owner-only permissions, and refusing a path that already exists so a planted
// artifact is rejected rather than adopted.
func TestCreateSecureFile_Other(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinelgo.new")

	f, err := winsec.CreateSecureFile(path)
	if err != nil {
		t.Fatalf("CreateSecureFile: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %04o, want 0600", mode)
	}

	if _, err := winsec.CreateSecureFile(path); err == nil {
		t.Error("CreateSecureFile must fail on an existing path, matching the " +
			"CREATE_NEW semantics the Windows build relies on")
	}
}
