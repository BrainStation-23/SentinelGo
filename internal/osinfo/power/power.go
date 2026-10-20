// Package power keeps the power_telemetry window sent with each inventory
// upload (#198): the CPU usage averaged over the whole time since the last
// successful upload, and the measured power draw where the OS reports it
// (#199), which the backend uses to estimate the device's energy use.
//
// The scheduler calls Sample on every agent-info tick, whether or not that
// tick uploads, and Snapshot/Commit around an upload. Commit is only called
// once the upload succeeded, so a failed upload keeps accumulating and no
// time is lost. The window lives in memory only: after a restart the first
// window starts at the restart.
package power

import (
	"errors"
	"math"
	"runtime"
	"sync"
	"time"

	gocpu "github.com/shirou/gopsutil/v4/cpu"

	"sentinelgo/internal/osinfo/shared"
)

// CPUTimes is a cumulative CPU-time reading across all CPUs, in seconds:
// Busy is the time spent doing work, Total includes idle time.
type CPUTimes struct {
	Busy  float64
	Total float64
}

// ReadCPUTimes reads the cumulative CPU times. It doesn't block, unlike
// gocpu.Percent, which sleeps for its sampling interval. A variable so tests
// can replace it.
var ReadCPUTimes = func() (CPUTimes, error) {
	ts, err := gocpu.Times(false)
	if err != nil {
		return CPUTimes{}, err
	}
	if len(ts) == 0 {
		return CPUTimes{}, errors.New("no CPU times reported")
	}
	return cpuTimesFrom(ts[0], runtime.GOOS), nil
}

// cpuTimesFrom computes busy and total time the way gocpu.Percent does: on
// Linux guest time is already counted in user and nice, and iowait counts as
// idle.
func cpuTimesFrom(t gocpu.TimesStat, goos string) CPUTimes {
	total := t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	if goos != "linux" {
		total += t.Guest + t.GuestNice
	}
	return CPUTimes{Busy: total - t.Idle - t.Iowait, Total: total}
}

// Window accumulates CPU time between successful uploads. The zero value is
// ready to use, and it is safe for concurrent use.
type Window struct {
	mu sync.Mutex

	start   time.Time // start of the current window
	last    time.Time // time of the last completed interval
	prev    CPUTimes  // previous reading, the baseline for the next interval
	hasPrev bool

	busy    float64
	total   float64
	samples int

	power powerSums
}

// powerSums accumulates the power readings of a window.
type powerSums struct {
	known    int // ticks where the OS reported the power source
	onAC     int
	measured int
	watts    float64 // sum over measured ticks
	bySource map[string]int
}

func (p *powerSums) add(r Reading) {
	if r.OnAC != nil {
		p.known++
		if *r.OnAC {
			p.onAC++
		}
	}
	if r.Source != "" && r.Watts > 0 {
		p.measured++
		p.watts += r.Watts
		if p.bySource == nil {
			p.bySource = map[string]int{}
		}
		p.bySource[r.Source]++
	}
}

func (p *powerSums) subtract(o powerSums) {
	p.known = max(0, p.known-o.known)
	p.onAC = max(0, p.onAC-o.onAC)
	p.measured = max(0, p.measured-o.measured)
	p.watts = math.Max(0, p.watts-o.watts)
	for k, n := range o.bySource {
		if p.bySource[k] -= n; p.bySource[k] <= 0 {
			delete(p.bySource, k)
		}
	}
	if p.measured == 0 {
		p.watts = 0
	}
}

func (p powerSums) clone() powerSums {
	c := p
	c.bySource = make(map[string]int, len(p.bySource))
	for k, n := range p.bySource {
		c.bySource[k] = n
	}
	return c
}

// source is the source with the most measured ticks; battery wins a tie.
func (p powerSums) source() string {
	best, bestN := "", 0
	for _, s := range []string{SourceBattery, SourceAppleSystemPower} {
		if n := p.bySource[s]; n > bestN {
			best, bestN = s, n
		}
	}
	return best
}

// Sample adds the interval since the previous reading to the window, with
// the tick's power reading p. The first reading only sets the baseline (and
// starts the window). An interval in which the counters went backwards or
// didn't advance, e.g. a counter that wrapped or was reset, is skipped and
// the reading becomes the new baseline. p is only counted with a completed
// interval, so the power counts are a subset of Samples.
func (w *Window) Sample(now time.Time, t CPUTimes, p Reading) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.start.IsZero() {
		w.start = now
	}
	if w.hasPrev {
		dBusy, dTotal := t.Busy-w.prev.Busy, t.Total-w.prev.Total
		if dTotal > 0 && dBusy >= 0 && dBusy <= dTotal {
			w.busy += dBusy
			w.total += dTotal
			w.samples++
			w.last = now
			w.power.add(p)
		}
	}
	w.prev, w.hasPrev = t, true
}

// Mark identifies what a Snapshot covered, so Commit removes exactly that
// even if more samples arrived in between.
type Mark struct {
	busy, total float64
	samples     int
	end         time.Time
	power       powerSums
}

// Snapshot returns the telemetry for the current window, or nil when no
// interval has completed yet (just started, or nothing since the last
// upload). interval is the configured time between samples.
func (w *Window) Snapshot(interval time.Duration) (*shared.PowerTelemetry, Mark) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.samples == 0 || w.total <= 0 {
		return nil, Mark{}
	}
	avg := math.Max(0, math.Min(100, w.busy/w.total*100))
	t := &shared.PowerTelemetry{
		WindowStart:           shared.ISOTime(w.start),
		WindowEnd:             shared.ISOTime(w.last),
		Samples:               w.samples,
		SampleIntervalSeconds: int(interval / time.Second),
		CPUUsageAvgPercent:    math.Round(avg*100) / 100,
	}
	if w.power.known > 0 {
		onAC := w.power.onAC
		t.OnACSamples = &onAC
	}
	if w.power.measured > 0 {
		t.MeasuredSamples = w.power.measured
		t.MeasuredWattsAvg = math.Round(w.power.watts/float64(w.power.measured)*100) / 100
		t.MeasuredSource = w.power.source()
	}
	return t, Mark{busy: w.busy, total: w.total, samples: w.samples, end: w.last, power: w.power.clone()}
}

// Commit starts a new window after the snapshot m was uploaded successfully.
// The new window starts where the uploaded one ended, and samples taken
// after the snapshot stay in it.
func (w *Window) Commit(m Mark) {
	if m.samples == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.busy = math.Max(0, w.busy-m.busy)
	w.total = math.Max(0, w.total-m.total)
	w.samples = max(0, w.samples-m.samples)
	w.power.subtract(m.power)
	w.start = m.end
}
