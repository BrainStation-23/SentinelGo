//go:build linux || darwin

package session

import (
	"fmt"
	"os"
	"path/filepath"
)

// userExecutable makes sure session users can run exe: the helper is
// launched as the logged-in user, not root, from the service's own binary.
// Replaced in tests.
var userExecutable = ensureUserExecutable

// ensureUserExecutable gives others read and execute on exe and its
// directory where they lack it (installers before #308 set both to 0750,
// so no helper could start), then checks every directory above is
// traversable. Write bits are never added: root keeps sole write access.
func ensureUserExecutable(exe string) error {
	if err := grantUserExec(exe); err != nil {
		return err
	}
	return userCanReach(exe)
}

// grantUserExec adds r-x for others to exe's directory and exe.
func grantUserExec(exe string) error {
	for _, p := range []string{filepath.Dir(exe), exe} {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		mode := fi.Mode().Perm()
		if mode&0o005 == 0o005 {
			continue
		}
		if err := os.Chmod(p, mode|0o005); err != nil { // #nosec G302 -- r-x for session users, who run this binary as their DLP helper; no write bits
			return fmt.Errorf("%s (mode %04o) is not accessible to session users, so their DLP helper can't run: %w", p, mode, err)
		}
	}
	return nil
}

// userCanReach reports the first path that stops a user other than its
// owner from running exe.
func userCanReach(exe string) error {
	need := os.FileMode(0o005) // the binary: read and execute
	for p := exe; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if mode := fi.Mode().Perm(); mode&need != need {
			return fmt.Errorf("%s (mode %04o) is not accessible to session users, so their DLP helper can't run", p, mode)
		}
		if parent := filepath.Dir(p); parent == p {
			return nil
		}
		need = 0o001 // directories: traverse
	}
}
