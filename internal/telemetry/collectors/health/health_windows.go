//go:build windows

package health

import (
	"context"

	"github.com/yusufpapurcu/wmi"
)

// The battery detail lives across three separate root\wmi classes, joined by
// InstanceName — see docs/telemetry/03-collection-matrix.md: Win32_Battery's
// own DesignCapacity is "almost always NULL", so the real values live here
// instead. Native WMI rather than PowerShell: four launches would cost
// roughly 3s against about 100ms for these queries, per the matrix doc's own
// measurement.
type winBatteryStatic struct {
	InstanceName     string
	DesignedCapacity uint32
	CycleCount       uint32
}

type winBatteryFullCharge struct {
	InstanceName        string
	FullChargedCapacity uint32
}

type winBatteryStatus struct {
	InstanceName      string
	PowerOnline       bool
	Charging          bool
	RemainingCapacity uint32
}

// platformBattery queries and joins all three classes. A query returning
// zero rows (rather than erroring) is the normal, expected shape on a
// desktop with no battery — not itself a warning.
//
// Named returns are required here, not decorative: on a WMI panic the defer
// below must still hand back a sensible (non-nil) Battery and an explanatory
// warning rather than the zero values a bare `recover()` would silently
// leave in place with unnamed returns.
func platformBattery(_ context.Context) (battery *Battery, warnings []string, source string) {
	defer func() {
		if r := recover(); r != nil {
			battery = &Battery{Present: false}
			warnings = append(warnings, "wmi query panicked")
			source = "wmi:root/wmi"
		}
	}()

	var statics []winBatteryStatic
	staticErr := wmi.QueryNamespace("SELECT InstanceName, DesignedCapacity, CycleCount FROM BatteryStaticData", &statics, `root\wmi`)

	var fullCharges []winBatteryFullCharge
	fullErr := wmi.QueryNamespace("SELECT InstanceName, FullChargedCapacity FROM BatteryFullChargedCapacity", &fullCharges, `root\wmi`)

	var statuses []winBatteryStatus
	statusErr := wmi.QueryNamespace("SELECT InstanceName, PowerOnline, Charging, RemainingCapacity FROM BatteryStatus", &statuses, `root\wmi`)

	if len(statics) == 0 && len(fullCharges) == 0 && len(statuses) == 0 {
		if staticErr != nil && fullErr != nil && statusErr != nil {
			// All three queries genuinely failed (e.g. WMI service down),
			// not just "no battery present" — surface that distinction via a
			// warning rather than reporting a confident CapNotPresent.
			return &Battery{Present: false}, []string{"root\\wmi battery classes query failed"}, "wmi:root/wmi"
		}
		return &Battery{Present: false}, nil, "wmi:root/wmi"
	}

	// Each of the three classes is queried and joined independently — one
	// failing (confirmed by hand: BatteryStaticData returns a genuine
	// "Generic failure" on some real ACPI battery WMI providers while the
	// other two classes succeed normally) must not discard the data the
	// other two classes did provide. There is no anchor class; the join key
	// is the union of instance names seen across whichever classes
	// succeeded.
	static := make(map[string]winBatteryStatic, len(statics))
	for _, s := range statics {
		static[s.InstanceName] = s
	}
	full := make(map[string]uint32, len(fullCharges))
	for _, f := range fullCharges {
		full[f.InstanceName] = f.FullChargedCapacity
	}
	status := make(map[string]winBatteryStatus, len(statuses))
	for _, s := range statuses {
		status[s.InstanceName] = s
	}

	instance := firstInstanceName(statics, fullCharges, statuses)

	var w []string
	if staticErr != nil {
		w = append(w, "BatteryStaticData query failed; design capacity and cycle count unavailable this cycle")
	}

	b := &Battery{Present: true}
	if s, ok := static[instance]; ok {
		if s.DesignedCapacity > 0 {
			v := uint64(s.DesignedCapacity)
			b.DesignCapacityMWh = &v
		}
		if s.CycleCount > 0 {
			v := int(s.CycleCount)
			b.CycleCount = &v
		}
	}

	fc, hasFull := full[instance]
	if hasFull && fc > 0 {
		v := uint64(fc)
		b.FullChargeCapacityMWh = &v
	}

	if st, ok := status[instance]; ok {
		charging := st.Charging
		b.Charging = &charging
		if hasFull && fc > 0 {
			pct := float64(st.RemainingCapacity) / float64(fc) * 100
			b.PercentRemaining = &pct
		}
	}

	return b, w, "wmi:root/wmi"
}

// firstInstanceName picks the join key: real laptops overwhelmingly report
// exactly one battery instance, so whichever class returned a row first
// names it. Checked in a fixed order so the result is deterministic rather
// than depending on which query happened to run first.
func firstInstanceName(statics []winBatteryStatic, fullCharges []winBatteryFullCharge, statuses []winBatteryStatus) string {
	if len(statics) > 0 {
		return statics[0].InstanceName
	}
	if len(fullCharges) > 0 {
		return fullCharges[0].InstanceName
	}
	if len(statuses) > 0 {
		return statuses[0].InstanceName
	}
	return ""
}
