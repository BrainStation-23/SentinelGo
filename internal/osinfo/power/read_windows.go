package power

import "github.com/yusufpapurcu/wmi"

// ReadPower queries root\wmi BatteryStatus in-process through WMI, so no
// PowerShell process is started on each tick.
var ReadPower = func() Reading {
	var rows []winBatteryStatus
	if err := wmi.QueryNamespace(
		"SELECT Active, PowerOnline, Discharging, Charging, DischargeRate FROM BatteryStatus",
		&rows, `root\wmi`); err != nil {
		return Reading{}
	}
	return windowsPowerReading(rows)
}
