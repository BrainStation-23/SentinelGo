//go:build darwin

package mdmenroll

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCommands records the commands the helper runs and runs answer (by
// default /usr/bin/true) instead.
type fakeCommands struct {
	mu   sync.Mutex
	runs [][]string
}

func (f *fakeCommands) install(t *testing.T, answer ...string) {
	t.Helper()
	if len(answer) == 0 {
		answer = []string{"/usr/bin/true"}
	}
	old := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, answer[0], answer[1:]...)
		f.mu.Lock()
		f.runs = append(f.runs, append([]string{name}, args...))
		f.mu.Unlock()
		return cmd
	}
	t.Cleanup(func() { execCommand = old })
}

// The profile is written fresh into the user's cache and opened, then
// System Settings opens where it's installed, then the instructions show.
// Profiles from earlier presentations are gone.
func TestOpenProfileForUser(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := paneDelay
	paneDelay = 0
	t.Cleanup(func() { paneDelay = old })
	f := &fakeCommands{}
	f.install(t)

	stale := filepath.Join(home, "Library", "Caches", "SentinelGo", "profiles", "old", profileName)
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("spent"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := OpenProfileForUser(profileName, []byte("<?xml new"), presentTitle, presentMessage); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("an earlier profile is still there: %v", err)
	}

	f.mu.Lock()
	runs := f.runs
	f.mu.Unlock()
	if len(runs) != 3 {
		t.Fatalf("ran %q", runs)
	}
	path := runs[0][len(runs[0])-1]
	if !strings.HasSuffix(runs[0][0], "/open") || filepath.Base(path) != profileName {
		t.Errorf("first ran %q", runs[0])
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "<?xml new" {
		t.Errorf("opened file holds %q, %v", b, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("profile file: %v %v", fi, err)
	}
	wantPane := installPane(macMajor(osProductVersion()))
	if !strings.HasSuffix(runs[1][0], "/open") || runs[1][1] != wantPane {
		t.Errorf("then ran %q, want open %s", runs[1], wantPane)
	}
	if runs[2][0] != "/usr/bin/osascript" || !strings.Contains(runs[2][2], "display dialog") {
		t.Errorf("then ran %q, want the instructions dialog", runs[2])
	}
}

func TestOfferEnrollForUser(t *testing.T) {
	for _, tc := range []struct {
		answer []string
		want   bool
	}{
		{[]string{"/bin/echo", "Enroll now"}, true},
		{[]string{"/bin/echo", "later"}, false},
		{[]string{"/usr/bin/false"}, false}, // Later: osascript's "User canceled"
	} {
		f := &fakeCommands{}
		f.install(t, tc.answer...)
		yes, err := OfferEnrollForUser(context.Background(), offerTitle, offerMessage)
		if err != nil || yes != tc.want {
			t.Errorf("%q: %v %v, want %v", tc.answer, yes, err, tc.want)
		}
		if len(f.runs) != 1 || f.runs[0][0] != "/usr/bin/osascript" || !strings.Contains(f.runs[0][2], `"Enroll now"`) {
			t.Errorf("ran %q", f.runs)
		}
	}

	// Nobody answered before the deadline.
	f := &fakeCommands{}
	f.install(t, "/bin/sleep", "5")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if yes, err := OfferEnrollForUser(ctx, offerTitle, offerMessage); yes || err != nil {
		t.Errorf("unanswered: %v %v", yes, err)
	}
}

// The service tells an active user from an away one with ioreg; on this Mac
// it must at least answer without failing.
func TestUserActiveRuns(t *testing.T) {
	_ = UserActive(Session{ID: "501", User: "test"})
}
