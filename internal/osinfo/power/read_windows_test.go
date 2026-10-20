package power

import (
	"sync/atomic"
	"testing"
	"time"
)

// A stalled WMI query must not hold up the tick, and must not pile up more
// blocked queries on later ticks.
func TestReadPowerStalledQuery(t *testing.T) {
	origQuery, origTimeout := queryBatteryStatus, wmiPowerTimeout
	t.Cleanup(func() { queryBatteryStatus, wmiPowerTimeout = origQuery, origTimeout })

	release := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	queryBatteryStatus = func() ([]winBatteryStatus, error) {
		calls.Add(1)
		<-release
		return []winBatteryStatus{{Active: true, Discharging: true, DischargeRate: 12000}}, nil
	}
	wmiPowerTimeout = 20 * time.Millisecond

	if r := ReadPower(); r.OnAC != nil || r.Watts != 0 {
		t.Fatalf("timed-out query must give an empty reading, got %+v", r)
	}
	start := time.Now()
	if r := ReadPower(); r.OnAC != nil || r.Watts != 0 {
		t.Fatalf("got %+v while the previous query is blocked", r)
	}
	if d := time.Since(start); d >= wmiPowerTimeout {
		t.Errorf("call while a query is blocked waited %v, want immediate", d)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("started %d queries, want 1 while the first is blocked", n)
	}

	// Once the stalled query returns, the next tick queries again.
	queryBatteryStatus = func() ([]winBatteryStatus, error) {
		calls.Add(1)
		defer close(done)
		return []winBatteryStatus{{Active: true, Discharging: true, DischargeRate: 12000}}, nil
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		wmiPowerMu.Lock()
		busy := wmiPowerInFlight
		wmiPowerMu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("in-flight flag not cleared after the query returned")
		}
		time.Sleep(time.Millisecond)
	}
	wmiPowerTimeout = 2 * time.Second
	if r := ReadPower(); r.Watts != 12 {
		t.Errorf("got %+v, want 12 W after the stalled query returned", r)
	}
	<-done
}
