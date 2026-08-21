//go:build darwin

package secureboot

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported without probing.
//
// Deciding CapNotPresent for an Intel Mac with no T2 would need the same
// system_profiler call Collect already makes, and running it twice per cycle to
// sharpen a capability is not worth roughly a second of wall time. A Mac that
// cannot answer surfaces as State "unknown" in the payload instead, which the
// change-detection layer already refuses to turn into an event.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSecureBoot reads the bridge OS (T2 / Apple silicon) boot policy.
func platformSecureBoot(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "system_profiler", "SPiBridgeDataType")
	if err != nil {
		return signal{
			State:    StateUnknown,
			Source:   "exec:system_profiler",
			Warnings: []string{"SPiBridgeDataType is unavailable on this Mac"},
		}
	}
	return signal{
		State:     parseBridgeOSSecurity(out),
		Mechanism: "exec:system_profiler:SPiBridgeDataType",
		Source:    "exec:system_profiler",
	}
}
