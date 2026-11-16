package cli

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"sentinelgo/internal/updater"
)

// UpdateWatchdogCommand is the hidden subcommand a self-update starts from a
// copy of the old binary (#503): it rolls the update back unless the new
// binary proves healthy in time.
const UpdateWatchdogCommand = updater.UpdateWatchdogCommand

// RunUpdateWatchdog runs `sentinelgo update-watchdog --marker <path>`. It logs
// to update_watchdog.log next to the marker, since it runs detached.
func RunUpdateWatchdog(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(UpdateWatchdogCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	marker := fs.String("marker", "", "path of the update marker to watch")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *marker == "" || !filepath.IsAbs(*marker) {
		_, _ = fmt.Fprintln(stderr, "update-watchdog: --marker must be an absolute path")
		return 2
	}
	logPath := filepath.Join(filepath.Dir(*marker), "update_watchdog.log")
	// #nosec G302 G304 -- fixed name next to the marker in the agent's config dir
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		defer func() { _ = f.Close() }()
		log.SetOutput(f)
	}
	return updater.RunWatchdog(*marker)
}
