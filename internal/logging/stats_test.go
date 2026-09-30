package logging

import (
	"sync"
	"testing"
)

func TestStatsCounter_AddAndSnapshot(t *testing.T) {
	var s statsCounter
	s.addCollected(3)
	s.addStored(2)
	s.addUploaded(1)
	s.addErrors(4)

	got := s.snapshot()
	want := LoggingStats{LogsCollected: 3, LogsStored: 2, LogsUploaded: 1, UploadErrors: 4}
	if got != want {
		t.Errorf("snapshot() = %+v, want %+v", got, want)
	}
}

func TestStatsCounter_AccumulatesAcrossMultipleAdds(t *testing.T) {
	var s statsCounter
	s.addCollected(1)
	s.addCollected(2)
	s.addStored(5)
	s.addStored(-1) // partial-failure rollback path
	s.addUploaded(0)
	s.addErrors(1)
	s.addErrors(1)

	got := s.snapshot()
	want := LoggingStats{LogsCollected: 3, LogsStored: 4, LogsUploaded: 0, UploadErrors: 2}
	if got != want {
		t.Errorf("snapshot() = %+v, want %+v", got, want)
	}
}

func TestStatsCounter_ZeroValueSnapshot(t *testing.T) {
	var s statsCounter
	got := s.snapshot()
	want := LoggingStats{}
	if got != want {
		t.Errorf("snapshot() of zero-value counter = %+v, want %+v", got, want)
	}
}

func TestStatsCounter_ConcurrentAdds(t *testing.T) {
	var s statsCounter
	var wg sync.WaitGroup
	const goroutines = 50

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s.addCollected(1)
			s.addStored(1)
			s.addUploaded(1)
			s.addErrors(1)
		}()
	}
	wg.Wait()

	got := s.snapshot()
	want := LoggingStats{
		LogsCollected: goroutines,
		LogsStored:    goroutines,
		LogsUploaded:  goroutines,
		UploadErrors:  goroutines,
	}
	if got != want {
		t.Errorf("snapshot() after concurrent adds = %+v, want %+v", got, want)
	}
}
