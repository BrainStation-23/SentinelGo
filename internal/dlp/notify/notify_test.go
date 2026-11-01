package notify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNotify_RateLimited(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	now := time.Unix(1_700_000_000, 0)
	n := &Notifier{
		now: func() time.Time { return now },
		send: func(title, body string) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, body)
			return nil
		},
	}
	n.Notify("t", "one")
	n.Notify("t", "two") // within 10 s: dropped
	now = now.Add(MinInterval)
	n.Notify("t", "three")
	n.Wait()
	slices.Sort(sent) // sends are asynchronous
	if !slices.Equal(sent, []string{"one", "three"}) {
		t.Errorf("sent = %v", sent)
	}
}

func TestNotify_FailureIsOnlyLogged(t *testing.T) {
	n := &Notifier{now: time.Now, send: func(string, string) error { return errors.New("no notification daemon") }}
	n.Notify("t", "b") // must not panic or block
	n.Wait()
}

func TestTrim(t *testing.T) {
	long := strings.Repeat("é", 1000)
	if got := []rune(trim(long)); len(got) != maxText {
		t.Errorf("trimmed to %d runes", len(got))
	}
	if trim("short") != "short" {
		t.Error("short text changed")
	}
}

// The text never lands in the command line where it could be parsed as
// script or options.
func TestCommand_TextNotInScript(t *testing.T) {
	evil := `"; Remove-Item C:\ -Recurse; $(rm -rf /) -x`
	cmd := command(context.Background(), "title", evil, LevelCritical)
	args := strings.Join(cmd.Args, " ")
	switch runtime.GOOS {
	case "windows", "darwin":
		if strings.Contains(args, evil) {
			t.Errorf("message in the command line: %s", args)
		}
		if !slices.Contains(cmd.Env, "SG_NOTIFY_BODY="+evil) {
			t.Error("message not passed through the environment")
		}
	case "linux":
		i := slices.Index(cmd.Args, "--")
		if i < 0 || cmd.Args[len(cmd.Args)-1] != evil || i > len(cmd.Args)-3 {
			t.Errorf("args = %q, want the text as plain arguments after --", cmd.Args)
		}
	}
}

// Live: shows a real notification (skipped with -short).
func TestPlatformSend_Live(t *testing.T) {
	if testing.Short() || runtime.GOOS != "windows" {
		t.Skip("shows a real notification; run on Windows without -short")
	}
	if err := platformSend("SentinelOps DLP (test)", "Test notification from the SentinelGo test suite", ""); err != nil {
		t.Errorf("toast: %v", err)
	}
}

// The level reaches each tool in its own form; DLP's notifications (no
// level) look as before.
func TestCommand_Level(t *testing.T) {
	for _, tc := range []struct{ level, mac, linux, win string }{
		{"", "", "", "SG_NOTIFY_LEVEL="},
		{LevelInfo, "", "--urgency=low", "SG_NOTIFY_LEVEL=info"},
		{LevelWarning, "SG_NOTIFY_SUBTITLE=Warning", "--urgency=normal", "SG_NOTIFY_LEVEL=warning"},
		{LevelCritical, "SG_NOTIFY_SUBTITLE=Critical", "--urgency=critical", "SG_NOTIFY_LEVEL=critical"},
	} {
		cmd := command(context.Background(), "t", "b", tc.level)
		args, env := strings.Join(cmd.Args, " "), strings.Join(cmd.Env, "\n")
		switch runtime.GOOS {
		case "darwin":
			if hasSub := strings.Contains(args, "subtitle"); hasSub != (tc.mac != "") || (tc.mac != "" && !slices.Contains(cmd.Env, tc.mac)) {
				t.Errorf("level %q: args %q", tc.level, args)
			}
		case "linux":
			if hasU := strings.Contains(args, "--urgency"); hasU != (tc.linux != "") || (tc.linux != "" && !slices.Contains(cmd.Args, tc.linux)) {
				t.Errorf("level %q: args %q", tc.level, cmd.Args)
			}
		case "windows":
			if !strings.Contains(env, tc.win) {
				t.Errorf("level %q: env lacks %s", tc.level, tc.win)
			}
		}
	}
}

// Show is not rate-limited, unlike the DLP Notifier.
func TestShow_NotRateLimited(t *testing.T) {
	if testing.Short() || os.Getenv("SENTINELGO_LIVE_NOTIFY") == "" {
		t.Skip("shows real notifications; set SENTINELGO_LIVE_NOTIFY=1")
	}
	for i, level := range []string{LevelInfo, LevelWarning, LevelCritical} {
		if err := Show("SentinelGo test "+level, "Notification "+string(rune('1'+i))+" of 3 from the test suite", level); err != nil {
			t.Errorf("%s: %v", level, err)
		}
	}
}

// Tools are run by absolute path, not looked up through PATH.
func TestCommand_AbsolutePath(t *testing.T) {
	cmd := command(context.Background(), "t", "b", "")
	if !filepath.IsAbs(cmd.Path) && runtime.GOOS != "windows" {
		t.Errorf("tool path %q is not absolute", cmd.Path)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(cmd.Path), `\windowspowershell\v1.0\powershell.exe`) {
		t.Errorf("powershell path = %q", cmd.Path)
	}
}

// A failed send's error doesn't contain the message.
func TestSendError_NoText(t *testing.T) {
	err := command(context.Background(), "t", "very-secret-body", LevelWarning).Run()
	if err != nil && strings.Contains(err.Error(), "very-secret-body") {
		t.Errorf("error leaks the message: %v", err)
	}
}
