package walk

import (
	"context"
	"errors"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

// fakeClock drives a Throttle: sleeping advances time.
type fakeClock struct {
	t      time.Time
	slept  []time.Duration
	onTick func()
}

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
	if c.onTick != nil {
		c.onTick()
	}
	return nil
}

func newTestThrottle(l yara.Limits, onBattery func() bool, cpu func() time.Duration) (*Throttle, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)}
	th := NewThrottle(l, onBattery, cpu)
	th.now, th.sleep = c.now, c.sleep
	return th, c
}

func TestThrottle_FileLimit(t *testing.T) {
	th, _ := newTestThrottle(yara.Limits{MaxFilesPerScan: 3}, nil, nil)
	for i := range 3 {
		if err := th.Wait(context.Background()); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	if err := th.Wait(context.Background()); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("4th file: %v", err)
	}
}

func TestThrottle_TimeLimit(t *testing.T) {
	th, c := newTestThrottle(yara.Limits{MaxScanMinutes: 1}, nil, nil)
	if err := th.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	if err := th.Wait(context.Background()); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("after a minute: %v", err)
	}
}

func TestThrottle_PausesOnBattery(t *testing.T) {
	battery := true
	th, c := newTestThrottle(yara.Limits{SkipOnBattery: true, MaxScanMinutes: 60}, func() bool { return battery }, nil)
	c.onTick = func() {
		if len(c.slept) == 3 {
			battery = false // plugged in after 90 s
		}
	}
	if err := th.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if th.BatteryWait != 3*batteryInterval {
		t.Fatalf("waited %v on battery, want %v", th.BatteryWait, 3*batteryInterval)
	}
	// Without skip_on_battery it never asks.
	th, _ = newTestThrottle(yara.Limits{}, func() bool { t.Fatal("power checked"); return true }, nil)
	if err := th.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestThrottle_BatteryCountsAgainstTimeLimit(t *testing.T) {
	th, _ := newTestThrottle(yara.Limits{SkipOnBattery: true, MaxScanMinutes: 2}, func() bool { return true }, nil)
	if err := th.Wait(context.Background()); !errors.Is(err, ErrLimitReached) {
		t.Fatalf("on battery for the whole window: %v", err)
	}
}

func TestThrottle_CPUBudget(t *testing.T) {
	var used time.Duration
	th, c := newTestThrottle(yara.Limits{MaxCPUPercent: 25}, nil, func() time.Duration { return used })
	ctx := context.Background()
	if err := th.Wait(ctx); err != nil { // first sample
		t.Fatal(err)
	}
	// 1 s of wall time, 1 s of CPU: 100% against a 25% budget. At 25% that
	// CPU needs 4 s, so the throttle waits 3 s (capped at 2 s per call).
	c.t = c.t.Add(time.Second)
	used = time.Second
	if err := th.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.slept; len(got) != 1 || got[0] != maxCPUPause {
		t.Fatalf("slept %v, want [%v]", got, maxCPUPause)
	}
	if err := th.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.slept; len(got) != 2 || got[1] != time.Second {
		t.Fatalf("slept %v, want a second 1s pause", got)
	}
	// Back under budget: no more pauses.
	if err := th.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.slept) != 2 {
		t.Fatalf("paused under budget: %v", c.slept)
	}
	if th.CPUWait != 3*time.Second {
		t.Fatalf("CPUWait = %v", th.CPUWait)
	}
}

func TestThrottle_ContextEndsPause(t *testing.T) {
	th := NewThrottle(yara.Limits{SkipOnBattery: true}, func() bool { return true }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := th.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
