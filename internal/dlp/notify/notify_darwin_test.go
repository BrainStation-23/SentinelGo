//go:build darwin

package notify

import (
	"context"
	"slices"
	"testing"
)

// terminal-notifier gets each value as its own argument, and the level as
// the subtitle.
func TestTerminalNotifierCmd(t *testing.T) {
	cmd := terminalNotifierCmd(context.Background(), "/usr/local/bin/terminal-notifier", "title", "body", LevelCritical)
	for _, pair := range [][2]string{{"-title", "title"}, {"-message", "body"}, {"-subtitle", "Critical"}} {
		i := slices.Index(cmd.Args, pair[0])
		if i < 0 || i+1 >= len(cmd.Args) || cmd.Args[i+1] != pair[1] {
			t.Errorf("args = %q, want %s %q", cmd.Args, pair[0], pair[1])
		}
	}
	if slices.Contains(cmd.Args, "-sender") {
		t.Error("-sender needs an installed app bundle and disables -appIcon")
	}
}
