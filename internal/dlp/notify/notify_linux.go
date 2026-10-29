//go:build linux

package notify

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// notifySendPaths are where notify-send is taken from (not through PATH).
var notifySendPaths = []string{"/usr/bin/notify-send", "/bin/notify-send", "/usr/local/bin/notify-send"}

func notifySend() string {
	for _, p := range notifySendPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return notifySendPaths[0] // fails with "not found", which is logged
}

// notify-send takes the text as separate arguments (no shell), after "--"
// so a message starting with "-" isn't read as an option.
func command(ctx context.Context, title, body string) *exec.Cmd {
	return exec.CommandContext(ctx, notifySend(), "--app-name=SentinelGo", "--", title, body) // #nosec G204 -- fixed tool path; text as plain arguments, no shell
}

func platformSend(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body).Run()
}
