//go:build darwin

package notify

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// The AppleScript reads title and body from the environment, so they are
// never parsed as script.
const notifyScript = `display notification (system attribute "SG_NOTIFY_BODY") with title (system attribute "SG_NOTIFY_TITLE")`

// levelScript adds the level as the subtitle.
const levelScript = notifyScript + ` subtitle (system attribute "SG_NOTIFY_SUBTITLE")`

// subtitles show a warning or critical level; info has none.
var subtitles = map[string]string{LevelWarning: "Warning", LevelCritical: "Critical"}

func command(ctx context.Context, title, body, level string) *exec.Cmd {
	script, env := notifyScript, []string{"SG_NOTIFY_TITLE=" + title, "SG_NOTIFY_BODY=" + body}
	if sub, ok := subtitles[level]; ok {
		script, env = levelScript, append(env, "SG_NOTIFY_SUBTITLE="+sub)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func platformSend(title, body, level string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body, level).Run()
}
