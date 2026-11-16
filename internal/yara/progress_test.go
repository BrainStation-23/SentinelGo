package yara

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func progressEvent() Event {
	return Event{EventID: "0d9e8f7a-5555-4b6c-9d0e-000000000001", Progress: &ScanProgress{
		ScanID: schID, Trigger: TriggerScheduled, Preset: PresetFull, FilesScanned: 10, FilesSkipped: 2,
		Errors: 1, Matches: 3, RootIndex: 1, RootsTotal: 4, ElapsedSeconds: 240}}
}

// The flat scan_progress shape the server reads (Compliance-OS #963), with
// no paths, and a round trip through the on-disk queue's JSON.
func TestEvent_ProgressShape(t *testing.T) {
	ev := progressEvent()
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"event_id", "kind", "scan_id", "trigger", "preset", "files_scanned", "files_skipped",
		"errors", "matches", "root_index", "roots_total", "elapsed_seconds"} {
		if _, ok := m[k]; !ok {
			t.Errorf("%s missing from %s", k, data)
		}
	}
	if m["kind"] != KindScanProgress || len(m) != 12 || strings.Contains(string(data), "path") {
		t.Errorf("progress JSON %s", data)
	}
	var back Event
	if err := json.Unmarshal(data, &back); err != nil || back.Progress == nil || *back.Progress != *ev.Progress || back.Kind() != KindScanProgress {
		t.Fatalf("round trip %+v, %v", back, err)
	}
}

func TestEvent_ProgressValidateRejects(t *testing.T) {
	for name, fn := range map[string]func(e *Event){
		"on_write": func(e *Event) { e.Progress.Trigger = TriggerOnWrite },
		"scan id":  func(e *Event) { e.Progress.ScanID = "x" },
		"preset":   func(e *Event) { e.Progress.Preset = "deep" },
		"negative": func(e *Event) { e.Progress.RootIndex = -1 },
		"two kinds": func(e *Event) {
			e.Summary = &ScanSummary{ScanID: schID, Trigger: TriggerScheduled, State: ScanCompleted}
		},
	} {
		ev := progressEvent()
		p := *ev.Progress
		ev.Progress = &p
		fn(&ev)
		if err := ev.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	if _, err := json.Marshal(Event{EventID: "x"}); err == nil {
		t.Error("an event without a body encoded")
	}
}

func TestBundle_ProgressInterval(t *testing.T) {
	for _, c := range []struct {
		cfg  *ScanProgressConfig
		want time.Duration
	}{
		{nil, 0},
		{&ScanProgressConfig{}, DefaultProgressInterval},
		{&ScanProgressConfig{IntervalSeconds: 120}, 2 * time.Minute},
		{&ScanProgressConfig{IntervalSeconds: 5}, MinProgressInterval},
	} {
		if got := (&Bundle{ScanProgress: c.cfg}).ProgressInterval(); got != c.want {
			t.Errorf("%+v: %v, want %v", c.cfg, got, c.want)
		}
	}
	b, err := Decode([]byte(strings.Replace(sampleBundle, `"schema_version": 1,`, `"schema_version": 1, "scan_progress": {"interval_seconds": 180},`, 1)))
	if err != nil || b.ProgressInterval() != 3*time.Minute {
		t.Fatalf("decoded %v, %v", b, err)
	}
}
