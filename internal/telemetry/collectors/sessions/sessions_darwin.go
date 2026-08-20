//go:build darwin

package sessions

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported unconditionally: `who` is a core
// BSD utility present on every supported macOS target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSessions lists sessions via `who`.
func platformSessions(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "who")
	if err != nil {
		return signal{Warnings: []string{"who failed to run"}, Err: err}
	}

	return signal{
		Sessions: parseWho(out),
		Source:   "exec:who",
	}
}
