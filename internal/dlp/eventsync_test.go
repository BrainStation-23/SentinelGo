package dlp

import (
	"strings"
	"testing"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/store"
)

func TestBatchesStayUnderLimit(t *testing.T) {
	var rows []store.DLPEventRow
	for i := range 5 {
		rows = append(rows, store.DLPEventRow{ID: int64(i), Event: events.Event{Excerpt: strings.Repeat("x", 300<<10)}})
	}
	rows = append(rows, store.DLPEventRow{ID: 9, Event: events.Event{Excerpt: strings.Repeat("y", 2<<20)}}) // too big alone
	got := batches(rows)
	total := 0
	for _, b := range got {
		total += len(b)
	}
	if total != len(rows) {
		t.Fatalf("batches hold %d rows, want %d", total, len(rows))
	}
	if len(got) != 4 || len(got[0]) != 2 || len(got[3]) != 1 || got[3][0].ID != 9 {
		t.Errorf("batch sizes = %v", func() []int {
			var n []int
			for _, b := range got {
				n = append(n, len(b))
			}
			return n
		}())
	}
}
