//go:build linux

package desktopproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sentinelgo/internal/binpath"
)

// noteName is the note in the user's state directory. Not the runtime
// directory: that is emptied at logout and reboot, while the GSettings and
// kioslaverc values outlive both.
const noteName = "upload-proxy.json"

// toolTimeout bounds one gsettings / kwriteconfig run.
const toolTimeout = 10 * time.Second

// New returns the Manager for the user running this process (the session
// helper), or nil when there is no home directory to keep the note in.
func New() *Manager {
	dir, err := stateDir()
	if err != nil {
		return nil
	}
	return NewManager(Options{
		Run:        run,
		Has:        has,
		Desktop:    os.Getenv("XDG_CURRENT_DESKTOP"),
		KDESession: os.Getenv("KDE_SESSION_VERSION"),
		NotePath:   filepath.Join(dir, "SentinelGo", noteName),
	})
}

// stateDir is $XDG_STATE_HOME, or ~/.local/state.
func stateDir() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state"), nil
}

func has(name string) bool {
	_, ok := lookup(name)
	return ok
}

// lookup finds a tool at its fixed system path, never through PATH.
func lookup(name string) (string, bool) {
	p, ok := binpath.Lookup(name)
	if !ok || !filepath.IsAbs(p) {
		return "", false
	}
	return p, true
}

func run(name string, args ...string) ([]byte, error) {
	p, ok := lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s not found", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, p, args...).Output() // #nosec G204 -- fixed desktop tools; arguments are fixed keys and our PAC URL
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return out, nil
}
