package mdmenroll

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sentinelgo/internal/binpath"
	"sentinelgo/internal/osinfo/shared"
)

// ConsoleSession returns the user logged in at the Mac's console: the owner
// of /dev/console. root owns it at the login window, which means nobody is.
func ConsoleSession() (Session, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return Session{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return Session{}, false
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	return Session{ID: uid, User: name}, true
}

// RenewADE asks macOS to (re-)enroll through Automated Device Enrollment.
// macOS shows the user the enrollment prompt.
func RenewADE(ctx context.Context) error {
	out, code, err := shared.RunCommandOutput("profiles", "renew", "-type", "enrollment")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("profiles renew exited %d: %s", code, firstLine(out))
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// execCommand is exec.CommandContext; a var for tests.
var execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tool path; the argument is a path we wrote
}

// profileTTL is how long a presented profile stays in the user's cache. By
// then System Settings has its own copy, and the profile is single-use.
const profileTTL = 30 * time.Minute

// OpenProfileForUser runs in the session helper, as the user: it writes the
// profile to the user's own cache and opens it, which registers it for
// review in System Settings. A root-owned file couldn't be opened by them.
var OpenProfileForUser = func(name string, data []byte) error {
	dir, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, "SentinelGo", "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	time.AfterFunc(profileTTL, func() { _ = os.Remove(path) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := execCommand(ctx, binpath.Resolve("open"), path)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("open: %v: %s", err, firstLine(string(out)))
	}
	return nil
}
