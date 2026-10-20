package power

// Measured power draw (#199). read_<os>.go gathers the raw values; the
// parsers here have no OS suffix so they compile and are tested on every
// platform.
//
// Only real readings of the whole machine's draw are reported:
//   - a battery while it discharges (its output is everything the machine
//     uses), and
//   - Apple's PowerTelemetryData.SystemPowerIn while on AC and not charging
//     (what the adapter delivers, all of it to the system).
//
// While charging, battery and adapter figures include the charge current, so
// they are not the machine's draw and aren't counted.

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Measurement sources reported in measured_source.
const (
	SourceBattery          = "battery"
	SourceAppleSystemPower = "apple_system_power"
)

// Plausible whole-machine draw, in watts. Readings outside it come from a
// broken sensor or driver and are dropped.
const (
	minPlausibleWatts = 0
	maxPlausibleWatts = 500
)

// Reading is one tick's power reading. OnAC is nil when the OS doesn't say
// (no battery or power supply information). Watts is 0 and Source "" when
// nothing was measured.
type Reading struct {
	OnAC   *bool
	Watts  float64
	Source string
}

func measured(watts float64, source string, onAC *bool) Reading {
	if !(watts > minPlausibleWatts && watts < maxPlausibleWatts) {
		return Reading{OnAC: onAC}
	}
	return Reading{OnAC: onAC, Watts: watts, Source: source}
}

// ── Linux ─────────────────────────────────────────────────────────────────────

// linuxSupply is one /sys/class/power_supply entry; each field is the
// trimmed content of the file of the same name ("" when missing).
type linuxSupply struct {
	Name       string
	Type       string // Battery, Mains, USB, ...
	Scope      string // "Device" for a peripheral's battery (mouse, headset)
	Status     string // Charging, Discharging, Full, Not charging, ...
	Online     string
	PowerNow   string // µW
	CurrentNow string // µA
	VoltageNow string // µV
}

// linuxPowerReading combines the power supplies. The machine is on AC when
// a mains or USB supply is online. Its draw is measured when at least one
// system battery is discharging, none is charging and no supply is online:
// the sum of the discharging batteries' power_now, or current_now ×
// voltage_now when power_now is missing.
func linuxPowerReading(supplies []linuxSupply) Reading {
	var onAC *bool
	var batteries []linuxSupply
	for _, s := range supplies {
		switch strings.ToLower(s.Type) {
		case "mains", "usb", "usb_c", "usb_pd":
			if s.Online == "" {
				continue
			}
			online := s.Online == "1"
			if onAC == nil || online {
				onAC = shared.Bool(online)
			}
		case "battery":
			if !strings.EqualFold(s.Scope, "Device") {
				batteries = append(batteries, s)
			}
		}
	}
	if onAC != nil && *onAC {
		return Reading{OnAC: onAC}
	}

	var watts float64
	discharging := false
	for _, b := range batteries {
		switch strings.ToLower(b.Status) {
		case "discharging":
			w, ok := linuxBatteryWatts(b)
			if !ok {
				return Reading{OnAC: onAC}
			}
			watts += w
			discharging = true
		case "charging":
			return Reading{OnAC: onAC}
		}
	}
	if !discharging {
		return Reading{OnAC: onAC}
	}
	if onAC == nil {
		onAC = shared.Bool(false)
	}
	return measured(watts, SourceBattery, onAC)
}

// readLinuxSupplies reads every power supply under root (normally
// /sys/class/power_supply).
func readLinuxSupplies(root string) []linuxSupply {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []linuxSupply
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		read := func(name string) string {
			b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed sysfs files under powerSupplyRoot
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
		out = append(out, linuxSupply{
			Name:       e.Name(),
			Type:       read("type"),
			Scope:      read("scope"),
			Status:     read("status"),
			Online:     read("online"),
			PowerNow:   read("power_now"),
			CurrentNow: read("current_now"),
			VoltageNow: read("voltage_now"),
		})
	}
	return out
}

// linuxBatteryWatts prefers power_now. Some drivers leave it at 0 while
// current_now and voltage_now are live, so 0 falls through to their product.
func linuxBatteryWatts(b linuxSupply) (float64, bool) {
	if p, ok := sysfsMicro(b.PowerNow); ok && p != 0 {
		return math.Abs(p), true
	}
	i, iok := sysfsMicro(b.CurrentNow)
	v, vok := sysfsMicro(b.VoltageNow)
	if !iok || !vok {
		return 0, false
	}
	return math.Abs(i * v), true
}

// sysfsMicro parses a sysfs value in micro-units (µW, µA, µV) into base
// units. Some drivers report a negative current while discharging.
func sysfsMicro(s string) (float64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(n) / 1e6, true
}

// ── Windows ───────────────────────────────────────────────────────────────────

// winBatteryStatus is one root\wmi BatteryStatus instance. DischargeRate is
// in mW.
type winBatteryStatus struct {
	Active        bool
	PowerOnline   bool
	Discharging   bool
	Charging      bool
	DischargeRate int32
}

// windowsPowerReading combines the BatteryStatus instances. The machine is
// on AC when any battery reports PowerOnline. Its draw is measured while on
// battery and discharging: the sum of the discharging batteries'
// DischargeRate. No instances (a desktop or VM) means nothing is known.
func windowsPowerReading(batteries []winBatteryStatus) Reading {
	if len(batteries) == 0 {
		return Reading{}
	}
	onAC := false
	for _, b := range batteries {
		onAC = onAC || b.PowerOnline
	}
	if onAC {
		return Reading{OnAC: shared.Bool(true)}
	}
	var watts float64
	discharging := false
	for _, b := range batteries {
		if b.Charging {
			return Reading{OnAC: shared.Bool(false)}
		}
		if b.Discharging {
			watts += math.Abs(float64(b.DischargeRate)) / 1000
			discharging = true
		}
	}
	if !discharging {
		return Reading{OnAC: shared.Bool(false)}
	}
	return measured(watts, SourceBattery, shared.Bool(false))
}

// ── macOS ─────────────────────────────────────────────────────────────────────

// macPowerReading reads `ioreg -rn AppleSmartBattery -a`: an array with
// the battery's properties. On battery (ExternalConnected false) the draw is
// InstantAmperage (mA, negative while discharging) × Voltage (mV). On AC and
// known not to be charging (IsCharging false) it is
// PowerTelemetryData.SystemPowerIn (mW), which Apple Silicon and T2 Macs
// report; while charging, or when IsCharging is missing, SystemPowerIn also
// feeds the battery, so it isn't the machine's draw.
func macPowerReading(plist any) Reading {
	arr, ok := plist.([]any)
	if !ok || len(arr) == 0 {
		return Reading{}
	}
	bat, ok := arr[0].(map[string]any)
	if !ok {
		return Reading{}
	}
	external, ok := bat["ExternalConnected"].(bool)
	if !ok {
		return Reading{}
	}
	onAC := shared.Bool(external)
	charging, chargingKnown := bat["IsCharging"].(bool)

	if external {
		if charging || !chargingKnown {
			return Reading{OnAC: onAC}
		}
		tel, _ := bat["PowerTelemetryData"].(map[string]any)
		mw, ok := shared.PlistNumber(tel["SystemPowerIn"])
		if !ok {
			return Reading{OnAC: onAC}
		}
		return measured(mw/1000, SourceAppleSystemPower, onAC)
	}

	ma, ok := firstNumber(bat, "InstantAmperage", "Amperage")
	if !ok {
		return Reading{OnAC: onAC}
	}
	mv, ok := firstNumber(bat, "Voltage", "AppleRawBatteryVoltage")
	if !ok {
		return Reading{OnAC: onAC}
	}
	return measured(math.Abs(ma*mv)/1e6, SourceBattery, onAC)
}

func firstNumber(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if n, ok := shared.PlistNumber(m[k]); ok {
			return n, true
		}
	}
	return 0, false
}
