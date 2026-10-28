//go:build linux

package notify

import (
	"context"
	"os/exec"
	"time"
)

// notify-send takes the text as separate arguments (no shell), after "--"
// so a message starting with "-" isn't read as an option.
func command(ctx context.Context, title, body string) *exec.Cmd {
	return exec.CommandContext(ctx, "notify-send", "--app-name=SentinelGo", "--", title, body) // #nosec G204 -- fixed tool; text as plain arguments, no shell
}

func platformSend(title, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return command(ctx, title, body).Run()
}
