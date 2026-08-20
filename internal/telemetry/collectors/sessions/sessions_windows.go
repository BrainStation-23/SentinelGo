//go:build windows

package sessions

import (
	"context"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported when quser is available. It ships
// with every Windows Server/Pro edition, but Home editions and some minimal
// installs omit the Remote Desktop Services components that provide it, so
// this is a real, worth-checking capability gate rather than an always-true
// one.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("quser"); err != nil {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

// platformSessions runs quser and parses its session table.
//
// quser's exit code is not documented to reliably mean "no sessions" versus
// "failed to run" — it is known to exit non-zero simply when nobody besides
// the caller is logged in — so RunCommandOutputContext is used to make sure
// output is never discarded because of that, the same caution this codebase
// applies to smartctl and yum.
func platformSessions(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "quser")
	if err != nil {
		return signal{Warnings: []string{"quser failed to run"}, Err: err}
	}

	return signal{
		Sessions: parseQuser(out),
		Source:   "exec:quser",
	}
}
