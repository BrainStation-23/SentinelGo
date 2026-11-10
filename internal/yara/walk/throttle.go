package walk

import (
	"context"
	"errors"
	"time"

	"sentinelgo/internal/osinfo/power"
	"sentinelgo/internal/yara"
)

// ErrLimitReached is returned by Throttle.Wait when the scan used up
// limits.max_scan_minutes or limits.max_files_per_scan. The scan ends as
// partial and resumes from its checkpoint in the next window.
var ErrLimitReached = errors.New("walk: scan limit reached")

// Throttle timing.
const (
	cpuWindow       = 10 * time.Second // CPU use is averaged over this
	maxCPUPause     = 2 * time.Second  // longest single pause for the CPU budget
	batteryInterval = 30 * time.Second // how often power is checked
)

// Throttle is the scan's Guard (#413):
//   - stops at max_files_per_scan files or max_scan_minutes (ErrLimitReached);
//   - with skip_on_battery, pauses while the device is on battery and
//     resumes on AC (the pause counts against max_scan_minutes);
//   - pauses whenever the scan's CPU use over the last 10 s is above
//     max_cpu_percent of one core.
type Throttle struct {
	limits    yara.Limits
	onBattery func() bool
	cpuTime   func() time.Duration
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error

	start       time.Time
	files       int
	samples     []cpuSample
	lastPower   time.Time
	battery     bool
	BatteryWait time.Duration // time spent paused on battery
	CPUWait     time.Duration // time spent paused for the CPU budget
}

type cpuSample struct {
	at  time.Time
	cpu time.Duration
}

// NewThrottle returns a Throttle for limits. onBattery reports whether the
// device runs on battery (OnBattery; nil never pauses). cpuTime returns the
// CPU time the scan's workers have used so far (nil: no CPU budget).
func NewThrottle(limits yara.Limits, onBattery func() bool, cpuTime func() time.Duration) *Throttle {
	return &Throttle{
		limits: limits, onBattery: onBattery, cpuTime: cpuTime,
		now: time.Now, sleep: sleepCtx,
	}
}

// OnBattery reports whether the device runs on battery now, from the
// battery collector. Unknown (desktops, no power information) is AC.
func OnBattery() bool {
	r := power.ReadPower()
	return r.OnAC != nil && !*r.OnAC
}

// Wait is called before each file.
func (t *Throttle) Wait(ctx context.Context) error {
	if t.start.IsZero() {
		t.start = t.now()
	}
	if err := t.overLimit(); err != nil {
		return err
	}
	if err := t.waitForAC(ctx); err != nil {
		return err
	}
	if err := t.cpuBudget(ctx); err != nil {
		return err
	}
	t.files++
	return nil
}

func (t *Throttle) overLimit() error {
	if t.limits.MaxFilesPerScan > 0 && t.files >= t.limits.MaxFilesPerScan {
		return ErrLimitReached
	}
	if t.limits.MaxScanMinutes > 0 && t.now().Sub(t.start) >= time.Duration(t.limits.MaxScanMinutes)*time.Minute {
		return ErrLimitReached
	}
	return nil
}

func (t *Throttle) waitForAC(ctx context.Context) error {
	if !t.limits.SkipOnBattery || t.onBattery == nil {
		return nil
	}
	for {
		if now := t.now(); t.lastPower.IsZero() || now.Sub(t.lastPower) >= batteryInterval {
			t.battery, t.lastPower = t.onBattery(), now
		}
		if !t.battery {
			return nil
		}
		if err := t.sleep(ctx, batteryInterval); err != nil {
			return err
		}
		t.BatteryWait += batteryInterval
		if err := t.overLimit(); err != nil {
			return err
		}
		t.samples = nil // the pause isn't CPU history
	}
}

// cpuBudget pauses long enough for the average over the window to fall back
// to the budget.
func (t *Throttle) cpuBudget(ctx context.Context) error {
	if t.cpuTime == nil || t.limits.MaxCPUPercent <= 0 {
		return nil
	}
	now, used := t.now(), t.cpuTime()
	t.samples = append(t.samples, cpuSample{now, used})
	for len(t.samples) > 1 && now.Sub(t.samples[1].at) >= cpuWindow {
		t.samples = t.samples[1:]
	}
	first := t.samples[0]
	elapsed, spent := now.Sub(first.at), used-first.cpu
	if elapsed <= 0 || spent <= 0 {
		return nil
	}
	budget := float64(t.limits.MaxCPUPercent) / 100
	// At the budget, spent CPU needs spent/budget of wall time.
	need := time.Duration(float64(spent)/budget) - elapsed
	if need <= 0 {
		return nil
	}
	need = min(need, maxCPUPause)
	if err := t.sleep(ctx, need); err != nil {
		return err
	}
	t.CPUWait += need
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}
