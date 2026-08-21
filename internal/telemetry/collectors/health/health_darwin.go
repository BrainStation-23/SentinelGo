//go:build darwin

package health

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// platformBattery reads `ioreg -rc AppleSmartBattery` and picks only the
// fields docs/telemetry/03-collection-matrix.md documents as unambiguous
// across both Intel and Apple Silicon Macs: CycleCount, IsCharging, and
// CurrentCapacity as a direct 0–100 percentage. MaxCapacity is deliberately
// NOT used for capacity math here — the matrix's own warning is that it
// returns 100 (a percentage) on M-series while the real mAh figure lives in
// AppleRawMaxCapacity, and getting that switch wrong produces a plausible
// but silently incorrect capacity, exactly the class of bug this package
// avoids elsewhere (see the SMART byte-decoding risk physicaldisks sidesteps
// entirely, and the Windows/Linux capacity paths in this same collector,
// which only combine values whose units are individually unambiguous).
func platformBattery(ctx context.Context) (*Battery, []string, string) {
	out, err := shared.RunCommandContext(ctx, "ioreg", "-rc", "AppleSmartBattery")
	if err != nil {
		return &Battery{Present: false}, []string{"ioreg failed to run"}, ""
	}

	fields := parseIoregFields(out)
	if len(fields) == 0 {
		return &Battery{Present: false}, nil, "exec:ioreg"
	}

	b := &Battery{Present: true}
	var warnings []string

	if cycles, ok := parseIoregInt(fields["CycleCount"]); ok {
		v := int(cycles)
		b.CycleCount = &v
	}
	if charging, ok := fields["IsCharging"]; ok {
		v := charging == "Yes"
		b.Charging = &v
	}
	if current, ok := parseIoregInt(fields["CurrentCapacity"]); ok {
		v := float64(current)
		b.PercentRemaining = &v
	}

	if design, ok := parseIoregInt(fields["DesignCapacity"]); ok {
		if voltage, vOk := parseIoregInt(fields["Voltage"]); vOk {
			v := mAhToMWh(design, voltage)
			b.DesignCapacityMWh = &v
		} else {
			warnings = append(warnings, "battery reports DesignCapacity but no Voltage to convert it")
		}
	}
	if raw, ok := parseIoregInt(fields["AppleRawMaxCapacity"]); ok {
		if voltage, vOk := parseIoregInt(fields["Voltage"]); vOk {
			v := mAhToMWh(raw, voltage)
			b.FullChargeCapacityMWh = &v
		}
	}

	return b, warnings, "exec:ioreg"
}
