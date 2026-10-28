package notify

import (
	"context"
	"errors"
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
	cmd := command(context.Background(), "title", evil)
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
	if err := platformSend("SentinelOps DLP (test)", "Test notification from the SentinelGo test suite"); err != nil {
		t.Errorf("toast: %v", err)
	}
}
