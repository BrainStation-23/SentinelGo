package power

import (
	"encoding/json"
	"testing"
	"time"

	gocpu "github.com/shirou/gopsutil/v4/cpu"
)

var t0 = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func TestFirstReadingOnlySetsBaseline(t *testing.T) {
	var w Window
	if tel, _ := w.Snapshot(5 * time.Minute); tel != nil {
		t.Fatalf("empty window must have no telemetry, got %+v", tel)
	}
	w.Sample(at(0), CPUTimes{Busy: 100, Total: 1000}, Reading{})
	if tel, _ := w.Snapshot(5 * time.Minute); tel != nil {
		t.Fatalf("no completed interval yet: telemetry must be omitted, got %+v", tel)
	}
}

func TestAccumulatesOverWindow(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{Busy: 0, Total: 0}, Reading{})
	w.Sample(at(5), CPUTimes{Busy: 30, Total: 300}, Reading{})   // 10%
	w.Sample(at(10), CPUTimes{Busy: 120, Total: 600}, Reading{}) // 30%
	tel, _ := w.Snapshot(5 * time.Minute)
	if tel == nil {
		t.Fatal("expected telemetry")
	}
	if tel.Samples != 2 || tel.SampleIntervalSeconds != 300 {
		t.Errorf("samples=%d interval=%d", tel.Samples, tel.SampleIntervalSeconds)
	}
	if tel.CPUUsageAvgPercent != 20 { // 120 busy / 600 total, not the mean of 10 and 30 by tick
		t.Errorf("avg = %v, want 20", tel.CPUUsageAvgPercent)
	}
	if tel.WindowStart != "2026-10-15T09:00:00Z" || tel.WindowEnd != "2026-10-15T09:10:00Z" {
		t.Errorf("window = %s .. %s", tel.WindowStart, tel.WindowEnd)
	}
}

func TestCommitResetsAfterSuccess(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{30, 300}, Reading{})
	_, m := w.Snapshot(5 * time.Minute)
	w.Commit(m)
	if tel, _ := w.Snapshot(5 * time.Minute); tel != nil {
		t.Fatalf("window must be empty right after a successful upload, got %+v", tel)
	}
	w.Sample(at(10), CPUTimes{330, 600}, Reading{}) // 100% of this interval
	tel, _ := w.Snapshot(5 * time.Minute)
	if tel == nil || tel.Samples != 1 || tel.CPUUsageAvgPercent != 100 {
		t.Fatalf("got %+v", tel)
	}
	if tel.WindowStart != "2026-10-15T09:05:00Z" {
		t.Errorf("new window must start where the uploaded one ended, got %s", tel.WindowStart)
	}
}

func TestFailedSendKeepsAccumulating(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{30, 300}, Reading{})
	_, _ = w.Snapshot(5 * time.Minute) // upload failed: no Commit
	w.Sample(at(10), CPUTimes{60, 600}, Reading{})
	tel, _ := w.Snapshot(5 * time.Minute)
	if tel == nil || tel.Samples != 2 || tel.WindowStart != "2026-10-15T09:00:00Z" {
		t.Fatalf("got %+v", tel)
	}
}

func TestCommitKeepsSamplesTakenAfterSnapshot(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{30, 300}, Reading{})
	_, m := w.Snapshot(5 * time.Minute)
	w.Sample(at(10), CPUTimes{330, 600}, Reading{})
	w.Commit(m)
	tel, _ := w.Snapshot(5 * time.Minute)
	if tel == nil || tel.Samples != 1 || tel.CPUUsageAvgPercent != 100 {
		t.Fatalf("got %+v", tel)
	}
}

func TestCommitOfEmptyMarkIsNoop(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{30, 300}, Reading{})
	w.Commit(Mark{})
	if tel, _ := w.Snapshot(5 * time.Minute); tel == nil || tel.Samples != 1 {
		t.Fatalf("got %+v", tel)
	}
}

func TestCounterWrapOrResetIsSkipped(t *testing.T) {
	cases := []struct {
		name string
		next CPUTimes
	}{
		{"total went backwards", CPUTimes{Busy: 10, Total: 50}},
		{"busy went backwards", CPUTimes{Busy: 10, Total: 900}},
		{"no time passed", CPUTimes{Busy: 30, Total: 300}},
		{"busy grew more than total", CPUTimes{Busy: 500, Total: 400}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var w Window
			w.Sample(at(0), CPUTimes{0, 0}, Reading{})
			w.Sample(at(5), CPUTimes{30, 300}, Reading{})
			w.Sample(at(10), c.next, Reading{}) // skipped, becomes the new baseline
			w.Sample(at(15), CPUTimes{Busy: c.next.Busy + 60, Total: c.next.Total + 300}, Reading{})
			tel, _ := w.Snapshot(5 * time.Minute)
			if tel == nil || tel.Samples != 2 {
				t.Fatalf("got %+v", tel)
			}
			if tel.CPUUsageAvgPercent != 15 { // (30+60)/(300+300)
				t.Errorf("avg = %v, want 15", tel.CPUUsageAvgPercent)
			}
			if tel.CPUUsageAvgPercent < 0 || tel.CPUUsageAvgPercent > 100 {
				t.Errorf("avg out of range: %v", tel.CPUUsageAvgPercent)
			}
		})
	}
}

func TestCPUTimesFrom(t *testing.T) {
	ts := gocpu.TimesStat{User: 10, System: 5, Idle: 80, Nice: 1, Iowait: 2, Irq: 1, Softirq: 1, Guest: 3, GuestNice: 1}
	if got := cpuTimesFrom(ts, "linux"); got.Total != 100 || got.Busy != 18 {
		t.Errorf("linux: %+v, want busy 18 total 100", got)
	}
	if got := cpuTimesFrom(ts, "windows"); got.Total != 104 || got.Busy != 22 {
		t.Errorf("windows: %+v, want busy 22 total 104", got)
	}
}

func TestReadCPUTimesOnHost(t *testing.T) {
	ct, err := ReadCPUTimes()
	if err != nil {
		t.Skipf("cpu times unavailable: %v", err)
	}
	if ct.Total <= 0 || ct.Busy < 0 || ct.Busy > ct.Total {
		t.Errorf("implausible reading %+v", ct)
	}
}

func TestTelemetryJSON(t *testing.T) {
	var w Window
	w.Sample(at(0), CPUTimes{0, 0}, Reading{})
	w.Sample(at(5), CPUTimes{22.2, 300}, Reading{})
	tel, _ := w.Snapshot(5 * time.Minute)
	b, _ := json.Marshal(tel)
	want := `{"window_start":"2026-10-15T09:00:00Z","window_end":"2026-10-15T09:05:00Z","samples":1,"sample_interval_seconds":300,"cpu_usage_avg_percent":7.4}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}
