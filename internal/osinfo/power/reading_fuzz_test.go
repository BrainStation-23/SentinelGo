package power

// Fuzz target for the power reading parsers (#199). They read sysfs values
// and ioreg output, which drivers and firmware shape, so parsing must never
// panic and must never report an implausible reading.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzPowerParsers$' -fuzztime=1m ./internal/osinfo/power/

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func FuzzPowerParsers(f *testing.F) {
	for _, s := range []string{
		ioregOnBattery, ioregOnACFull, ioregOnACCharging, ioregIntelOnAC,
		"", "0", "-1", "11800000", "99999999999999999999", "-9223372036854775808", "1e9", "Discharging",
		"<plist><array><dict><key>ExternalConnected</key><false/><key>InstantAmperage</key><integer>18446744073709551615</integer><key>Voltage</key><integer>9223372036854775807</integer></dict></array></plist>",
		"<plist><array><dict><key>ExternalConnected</key><true/><key>PowerTelemetryData</key><dict><key>SystemPowerIn</key><real>1e308</real></dict></dict></array></plist>",
	} {
		f.Add(s, int32(len(s)))
	}

	f.Fuzz(func(t *testing.T, s string, rate int32) {
		check := func(r Reading) {
			if r.Source != "" && !(r.Watts > minPlausibleWatts && r.Watts < maxPlausibleWatts) {
				t.Fatalf("implausible reading reported: %+v", r)
			}
		}

		plist, _ := shared.PlistFromOutput(s)
		check(macPowerReading(plist))

		check(linuxPowerReading([]linuxSupply{
			{Type: "Mains", Online: s},
			{Type: "Battery", Status: "Discharging", PowerNow: s},
			{Type: "Battery", Status: s, CurrentNow: s, VoltageNow: s},
		}))

		check(windowsPowerReading([]winBatteryStatus{{Discharging: true, DischargeRate: rate}}))
	})
}
