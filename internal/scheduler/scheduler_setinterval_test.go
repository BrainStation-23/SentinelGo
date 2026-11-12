package scheduler_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

func TestSetInterval_BeforeStart(t *testing.T) {
	s := scheduler.NewScheduler()
	if err := s.AddTask(&scheduler.Task{Name: "software-sync", Interval: time.Minute, Enabled: true,
		Handler: func(context.Context, *config.Config, *authsvc.Service) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetInterval("software-sync", 15*time.Minute); err != nil {
		t.Fatalf("SetInterval: %v", err)
	}
	if got := s.GetTaskStatus()["software-sync"].Interval; got != 15*time.Minute {
		t.Errorf("interval = %v, want 15m", got)
	}
	if err := s.SetInterval("missing", time.Minute); err == nil {
		t.Error("SetInterval(missing task) = nil error")
	}
	if err := s.SetInterval("software-sync", 0); err == nil {
		t.Error("SetInterval(0) = nil error")
	}
}

// TestSetInterval_WhileRunning shortens a running task's interval and
// expects the ticker to follow within a few heartbeats.
func TestSetInterval_WhileRunning(t *testing.T) {
	var runs atomic.Int32
	s := scheduler.NewScheduler()
	if err := s.AddTask(&scheduler.Task{Name: "services-collect", Interval: time.Hour, Enabled: true,
		Handler: func(context.Context, *config.Config, *authsvc.Service) error {
			runs.Add(1)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(&config.Config{}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)

	initial := runs.Load() // the initial run at Start
	if err := s.SetInterval("services-collect", 500*time.Millisecond); err != nil {
		t.Fatalf("SetInterval: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.GetTaskStatus()["services-collect"].Interval == 500*time.Millisecond && runs.Load() > initial {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("interval = %v, runs = %d (initial %d): the running ticker did not follow SetInterval",
		s.GetTaskStatus()["services-collect"].Interval, runs.Load(), initial)
}
