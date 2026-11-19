package mdmenroll

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/binpath"
	"sentinelgo/internal/dlp/notify"
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

// UserActive runs in the service, as root: the user of s is at the Mac when
// their screen isn't locked and the keyboard, mouse or trackpad was used in
// the last activeIdle. What ioreg can't tell counts as active, so a Mac
// whose ioreg changes still gets the profile.
func UserActive(s Session) bool {
	if out, err := shared.RunCommand("ioreg", "-n", "Root", "-d1", "-a"); err == nil {
		if locked, ok := consoleLocked(out, s.ID); ok && locked {
			return false
		}
	}
	if out, err := shared.RunCommand("ioreg", "-r", "-c", "IOHIDSystem", "-d1", "-a"); err == nil {
		if idle, ok := hidIdle(out); ok && idle >= activeIdle {
			return false
		}
	}
	return true
}

// execCommand is exec.CommandContext; a var for tests.
var execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tool path; the arguments are a path we wrote, a fixed pane, or a fixed script
}

// profileTTL is how long a presented profile stays in the user's cache. By
// then System Settings has its own copy, and the profile is single-use.
const profileTTL = 30 * time.Minute

// paneDelay lets System Settings register the downloaded profile before
// its pane is opened.
var paneDelay = time.Second

// dialogWait bounds how long the instructions stay on screen.
const dialogWait = 10 * time.Minute

// OpenProfileForUser runs in the session helper, as the user (#350, #545).
// It writes the profile to the user's own cache and opens it, which
// registers it for review in System Settings; a root-owned file couldn't be
// opened by them. Profiles from earlier presentations are deleted first:
// their challenge is spent or superseded. Then it opens System Settings at
// Device Management (Profiles on macOS 12 and earlier) and shows title and
// message in a dialog, without waiting for it.
var OpenProfileForUser = func(name string, data []byte, title, message string) error {
	dir, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, "SentinelGo", "profiles")
	_ = os.RemoveAll(dir)
	// Its own folder, so an earlier presentation's cleanup can't remove it.
	dir = filepath.Join(dir, strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	time.AfterFunc(profileTTL, func() { _ = os.RemoveAll(dir) })

	if err := openFor(path); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	time.Sleep(paneDelay)
	pane := installPane(macMajor(osProductVersion()))
	if err := openFor(pane); err != nil {
		// The profile is registered; the instructions say where it is.
		log.Printf("Session helper: System Settings not opened at %s: %v", pane, err)
	}
	if title != "" {
		showInstructions(title, message)
	}
	return nil
}

// openFor runs `open target` as the helper's user.
func openFor(target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := execCommand(ctx, binpath.Resolve("open"), target).CombinedOutput(); err != nil {
		return fmt.Errorf("open: %v: %s", err, firstLine(string(out)))
	}
	return nil
}

// osProductVersion is kern.osproductversion, e.g. "15.1".
func osProductVersion() string {
	v, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return v
}

// The dialogs read their text from the environment, so it is never parsed
// as script.
const (
	instructionsScript = `display dialog (system attribute "SG_MSG") with title (system attribute "SG_TITLE") buttons {"OK"} default button "OK" with icon note giving up after 600`
	offerScript        = `set r to display dialog (system attribute "SG_MSG") with title (system attribute "SG_TITLE") buttons {"Later", "Enroll now"} default button "Enroll now" cancel button "Later" with icon caution giving up after 600
if gave up of r then return "later"
return button returned of r`
)

func dialogCommand(ctx context.Context, script, title, message string) *exec.Cmd {
	cmd := execCommand(ctx, "/usr/bin/osascript", "-e", script)
	cmd.Env = append(os.Environ(), "SG_TITLE="+title, "SG_MSG="+message)
	return cmd
}

// showInstructions shows the dialog that says what to click, over System
// Settings, and returns at once. If it can't, a notification says it.
func showInstructions(title, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogWait+time.Minute)
	cmd := dialogCommand(ctx, instructionsScript, title, message)
	if err := cmd.Start(); err != nil {
		cancel()
		log.Printf("Session helper: enrollment instructions not shown as a dialog: %v", err)
		if err := notify.Show(title, message, notify.LevelWarning); err != nil {
			log.Printf("Session helper: enrollment instructions not shown: %v", err)
		}
		return
	}
	go func() {
		defer cancel()
		_ = cmd.Wait()
	}()
}

// OfferEnrollForUser runs in the session helper, as the user: the Enroll
// now dialog (#545). true means Enroll now; Later, closing it or leaving it
// unanswered is false.
var OfferEnrollForUser = func(ctx context.Context, title, message string) (bool, error) {
	out, err := dialogCommand(ctx, offerScript, title, message).Output()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee), ctx.Err() != nil:
		return false, nil // Later (osascript's "User canceled"), or nobody answered
	case err != nil:
		return false, err
	}
	return strings.TrimSpace(string(out)) == "Enroll now", nil
}

// OpenURLForUser is nil: enrollment links are Windows'.
var OpenURLForUser func(url string) error

// RegisterWindows and UnregisterWindows are Windows'.
var (
	RegisterWindows   func(upn, discoveryURL, accessToken string) error
	UnregisterWindows func(enrollmentID string) error
)
