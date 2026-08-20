//go:build darwin

package osdetail

import (
	"context"
	"os"
	"strings"
	"time"
)

// platformExtra reads the macOS-only best-effort fields.
//
// PendingReboot is deliberately left nil (undetermined) on macOS: there is no
// reliable per-cycle signal without a patches/software-update collector,
// which does not exist yet (docs/telemetry roadmap Phase D). Reporting a
// guessed false here would repeat exactly the "confident but fabricated"
// mistake the directory-join collector review caught; nil is the honest
// answer until that collector exists.
func platformExtra(_ context.Context) (ex extra) {
	var sources []string

	// .AppleSetupDone is written once by Setup Assistant during first boot
	// after installation and never modified again, so its mtime is a
	// reliable proxy for birth time without needing platform-specific
	// syscalls to read the real filesystem birth timestamp.
	if info, err := os.Stat("/var/db/.AppleSetupDone"); err == nil {
		ex.InstallDate = info.ModTime().UTC().Format(time.RFC3339)
		sources = append(sources, "stat:/var/db/.AppleSetupDone")
	} else {
		ex.Warnings = append(ex.Warnings, "install date marker file unreadable")
	}

	// ActivationStatus has no macOS concept and is left empty.

	ex.Source = strings.Join(sources, ", ")
	return ex
}
