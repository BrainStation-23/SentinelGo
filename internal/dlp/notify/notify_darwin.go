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

func command(ctx context.Context, title, body string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "osascript", "-e", notifyScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(os.Environ(), "SG_NOTIFY_TITLE="+title, "SG_NOTIFY_BODY="+body)
	return cmd
}

func platformSend(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body).Run()
}
