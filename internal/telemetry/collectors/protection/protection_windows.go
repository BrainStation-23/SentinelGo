//go:build windows

package protection

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// Windows exposes both controls through Defender's status API, whether or not
// Defender itself is the active anti-malware product: a third-party AV
// registers with Windows Security and Get-MpComputerStatus keeps answering.
const (
	realtimeProtectionCapability = tel.CapSupported
	tamperProtectionCapability   = tel.CapSupported
)

// defenderQuery projects only the two properties this section reports.
//
// $ErrorActionPreference plus try/catch is load-bearing for the same reason the
// encryption collector documents: Get-MpComputerStatus signals "the Defender
// service is unavailable" through a NON-terminating error and still exits 0, so
// without forcing it terminating the collector would read empty stdout as a
// successful "protection is off" — the exact false critical alert this section
// must never produce.
const defenderQuery = `$ErrorActionPreference = 'Stop'
try {
	Get-MpComputerStatus |
		Select-Object RealTimeProtectionEnabled,IsTamperProtected |
		ConvertTo-Json -Compress
} catch {
	exit 1
}`

func platformProtection(ctx context.Context) signal {
	var warnings []string

	firewall := Firewall{State: StateUnknown, Mechanism: "exec:netsh"}
	if out, _, err := shared.RunCommandOutputContext(ctx,
		"netsh", "advfirewall", "show", "allprofiles", "state"); err == nil {
		firewall.Profiles = parseNetshFirewall(out)
		firewall.State = firewallStateFrom(firewall.Profiles)
	} else {
		warnings = append(warnings, "netsh advfirewall query failed")
	}
	if firewall.State == StateUnknown && len(firewall.Profiles) == 0 {
		warnings = append(warnings, "no firewall profiles were reported")
	}

	realtime := Control{State: StateUnknown, Product: defenderProduct}
	tamper := Control{State: StateUnknown, Product: defenderProduct}

	out, err := shared.RunCommandContext(ctx, "powershell", "-NoProfile", "-Command", defenderQuery)
	switch {
	case err != nil:
		warnings = append(warnings, "Get-MpComputerStatus did not return a result")
	default:
		status, ok := parseDefenderStatus(out)
		if !ok {
			warnings = append(warnings, "Get-MpComputerStatus returned unparseable JSON")
			break
		}
		realtime = controlFromBool(status.RealTimeProtectionEnabled, defenderProduct)
		tamper = controlFromBool(status.IsTamperProtected, defenderProduct)
	}

	return signal{
		Payload: Payload{
			Firewall:           firewall,
			RealtimeProtection: realtime,
			TamperProtection:   tamper,
		},
		Source:   "exec:netsh+powershell:Get-MpComputerStatus",
		Warnings: warnings,
	}
}

const defenderProduct = "Microsoft Defender"
