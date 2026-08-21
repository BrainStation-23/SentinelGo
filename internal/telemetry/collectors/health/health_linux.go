//go:build linux

package health

import (
	"context"
	"os"
	"strconv"
	"strings"
)

const powerSupplyDir = "/sys/class/power_supply"

// platformBattery enumerates /sys/class/power_supply/* by type == "Battery"
// rather than hardcoding BAT0 — docs/telemetry/03-collection-matrix.md notes
// that misses CMB0, BATT and macsmc-battery. It also handles the
// matrix-documented unit trap: if energy_* exists the unit is µWh;
// otherwise charge_* is µAh and milliwatt-hours require
// (charge_µAh × voltage_µV) / 1e9 — mixing the two is "the classic bug".
func platformBattery(_ context.Context) (*Battery, []string, string) {
	entries, err := os.ReadDir(powerSupplyDir)
	if err != nil {
		return &Battery{Present: false}, []string{"/sys/class/power_supply unreadable"}, ""
	}

	for _, entry := range entries {
		path := powerSupplyDir + "/" + entry.Name()
		typ, err := readSysfsString(path + "/type")
		if err != nil || typ != "Battery" {
			continue
		}
		return readBatteryDir(path)
	}

	return &Battery{Present: false}, nil, "sysfs:" + powerSupplyDir
}

func readBatteryDir(path string) (*Battery, []string, string) {
	b := &Battery{Present: true}
	var warnings []string

	if cycles, err := readSysfsInt(path + "/cycle_count"); err == nil {
		v := int(cycles)
		b.CycleCount = &v
	}

	if status, err := readSysfsString(path + "/status"); err == nil {
		charging := status == "Charging"
		b.Charging = &charging
	}

	// energy_* is already in µWh, directly convertible to mWh. charge_* is
	// in µAh and needs the voltage to convert to a capacity in mWh at all —
	// the matrix-documented trap this function exists to avoid.
	if design, err := readSysfsInt(path + "/energy_full_design"); err == nil {
		v := uint64(design) / 1000
		b.DesignCapacityMWh = &v
	} else if design, err := readSysfsInt(path + "/charge_full_design"); err == nil {
		if voltage, vErr := readSysfsInt(path + "/voltage_now"); vErr == nil {
			v := microAhToMWh(design, voltage)
			b.DesignCapacityMWh = &v
		} else {
			warnings = append(warnings, "battery reports charge_full_design but no voltage_now to convert it")
		}
	}

	if full, err := readSysfsInt(path + "/energy_full"); err == nil {
		v := uint64(full) / 1000
		b.FullChargeCapacityMWh = &v
	} else if full, err := readSysfsInt(path + "/charge_full"); err == nil {
		if voltage, vErr := readSysfsInt(path + "/voltage_now"); vErr == nil {
			v := microAhToMWh(full, voltage)
			b.FullChargeCapacityMWh = &v
		}
	}

	if capacity, err := readSysfsInt(path + "/capacity"); err == nil {
		v := float64(capacity)
		b.PercentRemaining = &v
	}

	return b, warnings, "sysfs:" + path
}

func readSysfsString(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed sysfs path under /sys/class/power_supply, not user input
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func readSysfsInt(path string) (int64, error) {
	s, err := readSysfsString(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}
