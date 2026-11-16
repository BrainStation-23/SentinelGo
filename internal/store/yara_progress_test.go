package store

import (
	"fmt"
	"testing"

	"sentinelgo/internal/yara"
)

func yaraProgress(i int, scan string) yara.Event {
	return yara.Event{EventID: fmt.Sprintf("0d9e8f7a-5555-4b6c-9d0e-%012d", i), Progress: &yara.ScanProgress{
		ScanID: scan, Trigger: yara.TriggerScheduled, FilesScanned: int64(i)}}
}

// A scan's latest progress replaces any not uploaded yet; its summary
// drops it. Other scans' progress stays.
func TestYARAEventStore_ProgressReplaced(t *testing.T) {
	s, _ := newYARAStore(t)
	scanA := yaraSummary(0).Summary.ScanID
	scanB := "b0b1c2d3-3333-4e5f-8a9b-0123456789ab"
	for _, ev := range []yara.Event{yaraProgress(1, scanA), yaraProgress(2, scanB), yaraProgress(3, scanA)} {
		if err := s.Add([]yara.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Event.Progress.ScanID != scanB || rows[1].Event.Progress.FilesScanned != 3 {
		t.Fatalf("pending %+v", rows)
	}
	if err := s.Add([]yara.Event{yaraSummary(9)}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.Pending(10)
	if len(rows) != 2 || rows[0].Event.Progress == nil || rows[0].Event.Progress.ScanID != scanB || rows[1].Event.Summary == nil {
		t.Fatalf("after the summary %+v", rows)
	}
}

// Re-adding a progress event that is still queued (a retry) is a no-op: it
// keeps its place, so the cap still evicts it before newer rows.
func TestYARAEventStore_ProgressRetryKeepsOrder(t *testing.T) {
	s, _ := newYARAStore(t)
	s.SetLimits(2, 1<<20, 10)
	p := yaraProgress(1, yaraSummary(0).Summary.ScanID)
	m := yaraSummary(5)
	m.Summary.ScanID = "c0b1c2d3-3333-4e5f-8a9b-0123456789ab" // another scan
	for _, evs := range [][]yara.Event{{p}, {m}, {p}} {
		if err := s.Add(evs); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.Pending(10)
	if len(rows) != 2 || rows[0].Event.EventID != p.EventID || rows[1].Event.EventID != m.EventID {
		t.Fatalf("after the retry %+v", rows)
	}
	if err := s.Add([]yara.Event{yaraSummary(6)}); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.Pending(10)
	if len(rows) != 2 || rows[0].Event.EventID != m.EventID {
		t.Fatalf("the cap evicted the wrong row: %+v", rows)
	}
}
