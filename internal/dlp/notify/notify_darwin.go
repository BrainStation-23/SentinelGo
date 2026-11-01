//go:build darwin

package notify

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// iconPath is the branded PNG placed at the install directory by install.sh.
const iconPath = "/opt/sentinelgo/sentinelgo.png"

// terminalNotifierPaths are fixed locations for terminal-notifier; we never
// search PATH to avoid resolving to an attacker-controlled binary.
var terminalNotifierPaths = []string{
	"/usr/local/bin/terminal-notifier",
	"/opt/homebrew/bin/terminal-notifier",
	"/opt/local/bin/terminal-notifier",
}

// findTerminalNotifier returns the first terminal-notifier binary found at a
// known absolute path, or "" when none is installed.
func findTerminalNotifier() string {
	for _, p := range terminalNotifierPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// terminalNotifierCmd builds a terminal-notifier invocation.
// Title, body, and the optional subtitle arrive via individual -flag arguments
// (never in a shell string), so no quoting or escaping is needed.
// The icon is included only when the PNG exists at the install path.
func terminalNotifierCmd(ctx context.Context, bin, title, body, level string) *exec.Cmd {
	args := []string{
		"-title", title,
		"-message", body,
	}
	if _, err := os.Stat(iconPath); err == nil {
		args = append(args, "-appIcon", iconPath)
	}
	// subtitles for elevated levels
	switch level {
	case LevelWarning:
		args = append(args, "-subtitle", "Warning")
	case LevelCritical:
		args = append(args, "-subtitle", "Critical")
	}
	return exec.CommandContext(ctx, bin, args...) // #nosec G204 -- fixed binary path; text as individual flag arguments, no shell
}

// The AppleScript reads title and body from the environment, so they are
// never parsed as script.
const notifyScript = `display notification (system attribute "SG_NOTIFY_BODY") with title (system attribute "SG_NOTIFY_TITLE")`

// levelScript adds the level as the subtitle.
const levelScript = notifyScript + ` subtitle (system attribute "SG_NOTIFY_SUBTITLE")`

// subtitles show a warning or critical level; info has none.
var subtitles = map[string]string{LevelWarning: "Warning", LevelCritical: "Critical"}

// command builds the osascript fallback invocation.
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

	// Prefer terminal-notifier: it supports -appIcon so we can show the
	// SentinelGo brand icon. Fall back to osascript on systems where it is
	// not installed (osascript is always present on macOS).
	if bin := findTerminalNotifier(); bin != "" {
		return terminalNotifierCmd(ctx, bin, title, body, level).Run()
	}
	return command(ctx, title, body, level).Run()
}
