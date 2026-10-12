//go:build windows

package artifact

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestFetch_WindowsACLApplied checks the artifacts dir gets winsec's protected
// DACL (no inherited entries, SYSTEM and Administrators granted) and that the
// downloaded file inherits it.
func TestFetch_WindowsACLApplied(t *testing.T) {
	c, _ := server(t, serveBytes([]byte("x")))
	dir := filepath.Join(t.TempDir(), "artifacts")
	paths, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("installer", []byte("x"))})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(dir): %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("artifacts dir DACL is not protected from inheritance")
	}
	sddl := sd.String()
	for _, want := range []string{";;;SY)", ";;;BA)"} {
		if !strings.Contains(sddl, want) {
			t.Errorf("dir SDDL %q lacks %s", sddl, want)
		}
	}
	if strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
		t.Errorf("dir SDDL %q grants a broad group", sddl)
	}

	fsd, err := windows.GetNamedSecurityInfo(paths["installer"], windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(file): %v", err)
	}
	if fs := fsd.String(); strings.Contains(fs, ";;;BU)") || strings.Contains(fs, ";;;WD)") || strings.Contains(fs, ";;;AU)") {
		t.Errorf("file SDDL %q grants a broad group", fs)
	}
}
