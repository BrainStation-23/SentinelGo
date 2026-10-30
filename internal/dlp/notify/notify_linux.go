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

// urgencies map a level to notify-send's urgency; DLP sends none.
var urgencies = map[string]string{LevelInfo: "low", LevelWarning: "normal", LevelCritical: "critical"}

// notify-send takes the text as separate arguments (no shell), after "--"
// so a message starting with "-" isn't read as an option.
func command(ctx context.Context, title, body, level string) *exec.Cmd {
	args := []string{"--app-name=SentinelGo"}
	if u, ok := urgencies[level]; ok {
		args = append(args, "--urgency="+u)
	}
	args = append(args, "--", title, body)
	return exec.CommandContext(ctx, notifySend(), args...) // #nosec G204 -- fixed tool path; text as plain arguments, no shell
}

func platformSend(title, body, level string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body, level).Run()
}
