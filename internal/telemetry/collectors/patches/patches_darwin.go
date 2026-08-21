//go:build darwin

package patches

import (
	"context"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// pendingListTimeout bounds `softwareupdate -l` independently of the
// caller's context — like the Windows Update COM search this mirrors, it can
// hit Apple's servers and take well over a minute, and collectors in one
// cycle share a single context with no per-collector deadline (see RunAll in
// collector.go).
const pendingListTimeout = 25 * time.Second

func platformUpdates(ctx context.Context) signal {
	var updates []Update
	var warnings []string
	var sources []string

	if out, err := shared.RunCommandContext(ctx, "softwareupdate", "--history"); err == nil {
		updates = append(updates, parseSoftwareupdateHistory(out)...)
		sources = append(sources, "exec:softwareupdate --history")
	} else {
		warnings = append(warnings, "softwareupdate --history failed to run")
	}

	listCtx, cancel := context.WithTimeout(ctx, pendingListTimeout)
	defer cancel()
	if out, err := shared.RunCommandContext(listCtx, "softwareupdate", "-l"); err == nil {
		updates = append(updates, parseSoftwareupdateList(out)...)
		sources = append(sources, "exec:softwareupdate -l")
	} else {
		warnings = append(warnings, "softwareupdate -l failed or timed out")
	}

	return signal{Updates: updates, Source: strings.Join(sources, ", "), Warnings: warnings}
}
