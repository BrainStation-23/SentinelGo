package power

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func onACString(r Reading) string {
	if r.OnAC == nil {
		return "unknown"
	}
	if *r.OnAC {
		return "ac"
	}
	return "battery"
}

func checkReading(t *testing.T, got Reading, wantAC string, wantWatts float64, wantSource string) {
	t.Helper()
	if s := onACString(got); s != wantAC {
		t.Errorf("power source = %s, want %s", s, wantAC)
	}
	if math.Abs(got.Watts-wantWatts) > 0.01 || got.Source != wantSource {
		t.Errorf("measured = %.3f W from %q, want %.3f W from %q", got.Watts, got.Source, wantWatts, wantSource)
	}
}

// ── Linux ─────────────────────────────────────────────────────────────────────

func TestLinuxPowerReading(t *testing.T) {
	ac := func(online string) linuxSupply { return linuxSupply{Name: "AC", Type: "Mains", Online: online} }
	bat := func(status, power, current, voltage string) linuxSupply {
		return linuxSupply{Name: "BAT0", Type: "Battery", Status: status, PowerNow: power, CurrentNow: current, VoltageNow: voltage}
	}
	cases := []struct {
		name     string
		supplies []linuxSupply
		ac       string
		watts    float64
		source   string
	}{
		{"desktop: nothing", nil, "unknown", 0, ""},
		{"ThinkPad on battery, power_now", []linuxSupply{ac("0"), bat("Discharging", "11800000", "", "")}, "battery", 11.8, SourceBattery},
		{"current × voltage fallback", []linuxSupply{ac("0"), bat("Discharging", "", "1000000", "12000000")}, "battery", 12, SourceBattery},
		{"negative current reported", []linuxSupply{ac("0"), bat("Discharging", "", "-850000", "11400000")}, "battery", 9.69, SourceBattery},
		{"two batteries discharging", []linuxSupply{ac("0"), bat("Discharging", "5000000", "", ""), {Name: "BAT1", Type: "Battery", Status: "Discharging", PowerNow: "3000000"}}, "battery", 8, SourceBattery},
		{"on AC and charging", []linuxSupply{ac("1"), bat("Charging", "25000000", "", "")}, "ac", 0, ""},
		{"on AC, full", []linuxSupply{ac("1"), bat("Full", "0", "", "")}, "ac", 0, ""},
		{"USB-C adapter online", []linuxSupply{{Name: "ucsi-source-psy-USBC000:001", Type: "USB", Online: "1"}, bat("Not charging", "0", "", "")}, "ac", 0, ""},
		{"one battery charging from the other", []linuxSupply{ac("0"), bat("Discharging", "5000000", "", ""), {Name: "BAT1", Type: "Battery", Status: "Charging", PowerNow: "3000000"}}, "battery", 0, ""},
		{"no AC entry, discharging", []linuxSupply{bat("Discharging", "7000000", "", "")}, "battery", 7, SourceBattery},
		{"peripheral battery ignored", []linuxSupply{ac("1"), {Name: "hidpp_battery_0", Type: "Battery", Scope: "Device", Status: "Discharging", PowerNow: "100000"}}, "ac", 0, ""},
		{"discharging without a reading", []linuxSupply{ac("0"), bat("Discharging", "", "", "")}, "battery", 0, ""},
		{"implausible 0 W", []linuxSupply{ac("0"), bat("Discharging", "0", "", "")}, "battery", 0, ""},
		{"power_now 0 falls back to current × voltage", []linuxSupply{ac("0"), bat("Discharging", "0", "1000000", "12000000")}, "battery", 12, SourceBattery},
		{"implausible 900 W", []linuxSupply{ac("0"), bat("Discharging", "900000000", "", "")}, "battery", 0, ""},
		{"garbage value", []linuxSupply{ac("0"), bat("Discharging", "lots", "", "")}, "battery", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkReading(t, linuxPowerReading(c.supplies), c.ac, c.watts, c.source)
		})
	}
}

func TestReadLinuxSuppliesFromSysfs(t *testing.T) {
	root := t.TempDir()
	write := func(dir, name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, name), []byte(content+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("AC", "type", "Mains")
	write("AC", "online", "0")
	write("BAT0", "type", "Battery")
	write("BAT0", "status", "Discharging")
	write("BAT0", "power_now", "11800000")

	got := linuxPowerReading(readLinuxSupplies(root))
	checkReading(t, got, "battery", 11.8, SourceBattery)
	if s := readLinuxSupplies(filepath.Join(root, "missing")); s != nil {
		t.Errorf("missing root must give no supplies, got %v", s)
	}
}

// ── Windows ───────────────────────────────────────────────────────────────────

func TestWindowsPowerReading(t *testing.T) {
	cases := []struct {
		name   string
		rows   []winBatteryStatus
		ac     string
		watts  float64
		source string
	}{
		{"desktop or VM: no instances", nil, "unknown", 0, ""},
		{"on battery", []winBatteryStatus{{Active: true, Discharging: true, DischargeRate: 11800}}, "battery", 11.8, SourceBattery},
		{"on AC, charging", []winBatteryStatus{{Active: true, PowerOnline: true, Charging: true, DischargeRate: 0}}, "ac", 0, ""},
		{"on AC, full", []winBatteryStatus{{Active: true, PowerOnline: true}}, "ac", 0, ""},
		{"two batteries", []winBatteryStatus{{Discharging: true, DischargeRate: 6000}, {Discharging: true, DischargeRate: 4500}}, "battery", 10.5, SourceBattery},
		{"one on AC wins", []winBatteryStatus{{Discharging: true, DischargeRate: 6000}, {PowerOnline: true}}, "ac", 0, ""},
		{"negative rate", []winBatteryStatus{{Discharging: true, DischargeRate: -9000}}, "battery", 9, SourceBattery},
		{"zero rate on battery", []winBatteryStatus{{Discharging: true, DischargeRate: 0}}, "battery", 0, ""},
		{"implausible rate", []winBatteryStatus{{Discharging: true, DischargeRate: 2147483647}}, "battery", 0, ""},
		{"on battery, idle", []winBatteryStatus{{Active: true}}, "battery", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkReading(t, windowsPowerReading(c.rows), c.ac, c.watts, c.source)
		})
	}
}

// ── macOS ─────────────────────────────────────────────────────────────────────

// ioregOnBattery is trimmed `ioreg -rn AppleSmartBattery -a` output from an
// Apple Silicon MacBook on battery: InstantAmperage is negative, which ioreg
// writes as an unsigned 64-bit number.
const ioregOnBattery = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>Amperage</key>
		<integer>18446744073709550622</integer>
		<key>AppleRawBatteryVoltage</key>
		<integer>12210</integer>
		<key>CurrentCapacity</key>
		<integer>81</integer>
		<key>ExternalConnected</key>
		<false/>
		<key>FullyCharged</key>
		<false/>
		<key>InstantAmperage</key>
		<integer>18446744073709550650</integer>
		<key>IsCharging</key>
		<false/>
		<key>PowerTelemetryData</key>
		<dict>
			<key>BatteryPower</key>
			<integer>11873</integer>
			<key>SystemLoad</key>
			<integer>11873</integer>
			<key>SystemPowerIn</key>
			<integer>0</integer>
		</dict>
		<key>Voltage</key>
		<integer>12200</integer>
	</dict>
</array>
</plist>`

const ioregOnACFull = `<plist version="1.0"><array><dict>
	<key>ExternalConnected</key><true/>
	<key>FullyCharged</key><true/>
	<key>InstantAmperage</key><integer>0</integer>
	<key>IsCharging</key><false/>
	<key>PowerTelemetryData</key><dict><key>SystemPowerIn</key><integer>8420</integer></dict>
	<key>Voltage</key><integer>13050</integer>
</dict></array></plist>`

const ioregOnACCharging = `<plist version="1.0"><array><dict>
	<key>ExternalConnected</key><true/>
	<key>InstantAmperage</key><integer>2950</integer>
	<key>IsCharging</key><true/>
	<key>PowerTelemetryData</key><dict><key>SystemPowerIn</key><integer>48210</integer></dict>
	<key>Voltage</key><integer>12600</integer>
</dict></array></plist>`

// Intel Macs without a T2 have no PowerTelemetryData.
const ioregIntelOnAC = `<plist version="1.0"><array><dict>
	<key>ExternalConnected</key><true/>
	<key>InstantAmperage</key><integer>0</integer>
	<key>IsCharging</key><false/>
	<key>Voltage</key><integer>12750</integer>
</dict></array></plist>`

func TestMacPowerReading(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		ac     string
		watts  float64
		source string
	}{
		{"on battery", ioregOnBattery, "battery", 11.785, SourceBattery}, // 966 mA × 12.2 V
		{"on AC, not charging", ioregOnACFull, "ac", 8.42, SourceAppleSystemPower},
		{"on AC, charging", ioregOnACCharging, "ac", 0, ""},
		{"Intel on AC", ioregIntelOnAC, "ac", 0, ""},
		{"on AC, IsCharging missing", `<plist><array><dict><key>ExternalConnected</key><true/><key>PowerTelemetryData</key><dict><key>SystemPowerIn</key><integer>48000</integer></dict></dict></array></plist>`, "ac", 0, ""},
		{"desktop Mac: empty array", `<plist version="1.0"><array/></plist>`, "unknown", 0, ""},
		{"no plist", "", "unknown", 0, ""},
		{"no ExternalConnected", `<plist><array><dict><key>Voltage</key><integer>1</integer></dict></array></plist>`, "unknown", 0, ""},
		{"on battery, no amperage", `<plist><array><dict><key>ExternalConnected</key><false/><key>Voltage</key><integer>12000</integer></dict></array></plist>`, "battery", 0, ""},
		{"Amperage fallback", `<plist><array><dict><key>ExternalConnected</key><false/><key>Amperage</key><integer>-1000</integer><key>Voltage</key><integer>12000</integer></dict></array></plist>`, "battery", 12, SourceBattery},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plist, _ := shared.PlistFromOutput(c.out)
			checkReading(t, macPowerReading(plist), c.ac, c.watts, c.source)
		})
	}
}

// ── window ────────────────────────────────────────────────────────────────────

func TestWindowAggregatesPower(t *testing.T) {
	onBattery := func(w float64) Reading { return Reading{OnAC: shared.Bool(false), Watts: w, Source: SourceBattery} }
	onAC := Reading{OnAC: shared.Bool(true)}

	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, onBattery(50)) // baseline: no interval, not counted
	w.Sample(at(5), CPUTimes{30, 300}, onAC)
	w.Sample(at(10), CPUTimes{60, 600}, onBattery(10))
	w.Sample(at(15), CPUTimes{90, 900}, onBattery(14))
	w.Sample(at(20), CPUTimes{120, 1200}, Reading{OnAC: shared.Bool(true), Watts: 8, Source: SourceAppleSystemPower})
	tel, m := w.Snapshot(5 * time.Minute)
	if tel == nil || tel.Samples != 4 {
		t.Fatalf("got %+v", tel)
	}
	if tel.OnACSamples == nil || *tel.OnACSamples != 2 {
		t.Errorf("on_ac_samples = %v, want 2", tel.OnACSamples)
	}
	if tel.MeasuredSamples != 3 || tel.MeasuredWattsAvg != 10.67 || tel.MeasuredSource != SourceBattery {
		t.Errorf("measured = %d × %.2f W from %q, want 3 × 10.67 W from battery", tel.MeasuredSamples, tel.MeasuredWattsAvg, tel.MeasuredSource)
	}

	w.Commit(m)
	w.Sample(at(25), CPUTimes{150, 1500}, Reading{OnAC: shared.Bool(true), Watts: 9, Source: SourceAppleSystemPower})
	tel, _ = w.Snapshot(5 * time.Minute)
	if tel.MeasuredSamples != 1 || tel.MeasuredWattsAvg != 9 || tel.MeasuredSource != SourceAppleSystemPower || *tel.OnACSamples != 1 {
		t.Errorf("after commit: %+v", tel)
	}
}

func TestWindowDesktopSendsNoPowerFields(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{30, 300}, Reading{})
	tel, _ := w.Snapshot(5 * time.Minute)
	if tel.OnACSamples != nil || tel.MeasuredSamples != 0 || tel.MeasuredWattsAvg != 0 || tel.MeasuredSource != "" {
		t.Errorf("a desktop must send no power fields: %+v", tel)
	}

	// On AC without a measurement (a non-Apple laptop): on_ac_samples only.
	w.Sample(at(10), CPUTimes{60, 600}, Reading{OnAC: shared.Bool(true)})
	tel, _ = w.Snapshot(5 * time.Minute)
	if tel.OnACSamples == nil || *tel.OnACSamples != 1 || tel.MeasuredSamples != 0 || tel.MeasuredSource != "" {
		t.Errorf("got %+v", tel)
	}
}

func TestReadPowerOnHost(t *testing.T) {
	r := ReadPower()
	if r.Source != "" && !(r.Watts > 0 && r.Watts < 500) {
		t.Errorf("implausible reading %+v", r)
	}
	t.Logf("host power reading: %s, %.2f W %s", onACString(r), r.Watts, r.Source)
}
