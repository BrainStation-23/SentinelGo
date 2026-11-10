package store

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

func yaraSummary(i int) yara.Event {
	return yara.Event{EventID: fmt.Sprintf("0d9e8f7a-4444-4b6c-9d0e-%012d", i), Summary: &yara.ScanSummary{
		ScanID: "a0b1c2d3-3333-4e5f-8a9b-0123456789ab", Trigger: yara.TriggerScheduled, State: yara.ScanCompleted,
		FilesScanned: int64(i),
	}}
}

func newYARAStore(t *testing.T) (*YARAEventStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), YARAEventsDBName)
	s, err := NewYARAEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestYARAEventStore_QueueAndDelete(t *testing.T) {
	s, path := newYARAStore(t)
	if err := s.Add([]yara.Event{yaraSummary(1), yaraSummary(2), yaraSummary(1)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Event.Summary.FilesScanned != 1 || rows[1].Event.EventID != yaraSummary(2).EventID {
		t.Fatalf("pending = %+v", rows)
	}
	if err := s.Delete([]int64{rows[0].ID}); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _ := s.Stats(); n != 1 {
		t.Fatalf("%d rows after delete", n)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("queue file is %v, want owner-only", info.Mode().Perm())
		}
	}
	// Survives a restart.
	_ = s.Close()
	s2, err := NewYARAEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if rows, _ := s2.Pending(10); len(rows) != 1 {
		t.Fatalf("after reopen: %d rows", len(rows))
	}
}

func TestYARAEventStore_CapDropsOldest(t *testing.T) {
	s, _ := newYARAStore(t)
	s.SetLimits(3, 1<<20, 10)
	for i := range 5 {
		if err := s.Add([]yara.Event{yaraSummary(i)}); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.Pending(10)
	if len(rows) != 3 || rows[0].Event.Summary.FilesScanned != 2 {
		t.Fatalf("kept %+v", rows)
	}
	if _, _, dropped, _ := s.Stats(); dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
}

func TestYARAEventStore_Reported(t *testing.T) {
	s, _ := newYARAStore(t)
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.SetLimits(DefaultYARAMaxRows, DefaultYARAMaxBytes, 2)
	if err := s.MarkReported([]string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Reported([]string{"a", "b", "c"})
	if err != nil || !got["a"] || !got["b"] || got["c"] {
		t.Fatalf("Reported = %v, %v", got, err)
	}
	// Over the cap, the oldest key goes.
	now = now.Add(time.Hour)
	if err := s.MarkReported([]string{"c"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Reported([]string{"a", "b", "c"}); len(got) != 2 || !got["c"] {
		t.Fatalf("after cap: %v", got)
	}
	// After the TTL nothing counts as reported.
	now = now.Add(YARAReportedTTL + time.Hour)
	if got, _ := s.Reported([]string{"a", "b", "c"}); len(got) != 0 {
		t.Fatalf("after TTL: %v", got)
	}
}
