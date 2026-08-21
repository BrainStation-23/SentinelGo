//go:build darwin

package protection

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// macOS ships XProtect, which is always-on malware scanning with no
// administrator-visible enable/disable switch, and has no tamper-protection
// control at all.
//
// Real-time protection is therefore CapUnsupported rather than CapNotPresent:
// the capability exists on the device, but the OS exposes no state for the
// agent to read. Tamper protection is CapNotPresent — there is no such control
// to expose. Reporting either as "enabled" because XProtect is always running
// would be an assertion the agent cannot actually verify.
const (
	realtimeProtectionCapability = tel.CapUnsupported
	tamperProtectionCapability   = tel.CapNotPresent
)

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func platformProtection(ctx context.Context) signal {
	firewall := Firewall{State: StateUnknown, Mechanism: "exec:socketfilterfw"}
	var warnings []string

	if out, err := shared.RunCommandContext(ctx, socketFilterFW, "--getglobalstate"); err == nil {
		firewall.Profiles = []Profile{parseSocketFilterFW(out)}
		firewall.State = firewallStateFrom(firewall.Profiles)
	} else {
		warnings = append(warnings, "socketfilterfw --getglobalstate failed")
	}

	return signal{
		Payload: Payload{
			Firewall:           firewall,
			RealtimeProtection: Control{State: StateUnknown},
			TamperProtection:   Control{State: StateUnknown},
		},
		Source:   "exec:socketfilterfw",
		Warnings: warnings,
	}
}
