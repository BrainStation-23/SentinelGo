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

// iconPath is the branded PNG placed at the install directory by install.sh.
// notify-send accepts an absolute file path or a named icon from the theme.
const iconPath = "/opt/sentinelgo/sentinelgo.png"

// urgencies map a level to notify-send's urgency; DLP sends none.
var urgencies = map[string]string{LevelInfo: "low", LevelWarning: "normal", LevelCritical: "critical"}

// command builds the notify-send invocation. Text arrives as plain arguments
// (after "--") so a message starting with "-" is never mis-read as an option.
// The icon is included only when the file is present at the install path;
// omitting it on a minimal system is preferable to an error.
func command(ctx context.Context, title, body, level string) *exec.Cmd {
	args := []string{"--app-name=SentinelGo"}
	if u, ok := urgencies[level]; ok {
		args = append(args, "--urgency="+u)
	}
	if _, err := os.Stat(iconPath); err == nil {
		args = append(args, "--icon="+iconPath)
	}
	args = append(args, "--", title, body)
	return exec.CommandContext(ctx, notifySend(), args...) // #nosec G204 -- fixed tool path; text as plain arguments, no shell
}

func platformSend(title, body, level string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body, level).Run()
}
