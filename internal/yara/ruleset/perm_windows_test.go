package ruleset

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// checkOwnerOnly: every entry has a protected DACL (no inherited ACEs) that
// grants nothing to Users, Authenticated Users or Everyone.
func checkOwnerOnly(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		sddl := sd.String()
		if !strings.Contains(sddl, "D:P") {
			t.Errorf("%s: DACL not protected: %s", p, sddl)
		}
		for _, sid := range []string{";BU)", ";AU)", ";WD)"} {
			if strings.Contains(sddl, sid) {
				t.Errorf("%s: grants %s: %s", p, sid, sddl)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
