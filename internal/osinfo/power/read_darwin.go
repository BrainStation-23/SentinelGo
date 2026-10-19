package power

import "sentinelgo/internal/osinfo/shared"

// ReadPower reads the battery's IORegistry entry with ioreg (resolved from
// its fixed path by internal/binpath).
var ReadPower = func() Reading {
	out, err := shared.RunCommand("ioreg", "-rn", "AppleSmartBattery", "-a")
	if err != nil {
		return Reading{}
	}
	plist, ok := shared.PlistFromOutput(out)
	if !ok {
		return Reading{}
	}
	return macPowerReading(plist)
}
