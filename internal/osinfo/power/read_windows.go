package power

import (
	"sync"
	"time"

	"github.com/yusufpapurcu/wmi"
)

// wmiPowerTimeout bounds how long a tick waits for the BatteryStatus query.
// A variable so tests can shorten it.
var wmiPowerTimeout = 10 * time.Second

// queryBatteryStatus runs the WMI query. A variable so tests can replace it.
var queryBatteryStatus = func() ([]winBatteryStatus, error) {
	var rows []winBatteryStatus
	err := wmi.QueryNamespace(
		"SELECT Active, PowerOnline, Discharging, Charging, DischargeRate FROM BatteryStatus",
		&rows, `root\wmi`)
	return rows, err
}

var (
	wmiPowerMu       sync.Mutex
	wmiPowerInFlight bool
)

// ReadPower queries root\wmi BatteryStatus in-process through WMI, so no
// PowerShell process is started on each tick. The wmi package can't cancel
// a query, so a stalled one is abandoned after wmiPowerTimeout rather than
// holding up the agent-info tick, and no new query starts until it returns:
// a hung WMI service then costs one blocked goroutine, not one per tick.
var ReadPower = func() Reading {
	wmiPowerMu.Lock()
	if wmiPowerInFlight {
		wmiPowerMu.Unlock()
		return Reading{}
	}
	wmiPowerInFlight = true
	wmiPowerMu.Unlock()

	ch := make(chan Reading, 1)
	go func() {
		defer func() {
			wmiPowerMu.Lock()
			wmiPowerInFlight = false
			wmiPowerMu.Unlock()
		}()
		rows, err := queryBatteryStatus()
		if err != nil {
			ch <- Reading{}
			return
		}
		ch <- windowsPowerReading(rows)
	}()

	timer := time.NewTimer(wmiPowerTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r
	case <-timer.C:
		return Reading{}
	}
}
