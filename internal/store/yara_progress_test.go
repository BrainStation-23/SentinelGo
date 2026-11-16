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
