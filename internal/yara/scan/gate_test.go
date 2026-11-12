package scan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Waiters get the worker by priority: on-demand, then on-write, then
// scheduled.
func TestGate_Priority(t *testing.T) {
	g := newGate()
	ctx := context.Background()
	if err := g.acquire(ctx, prioScheduled); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var order []priority
	var wg sync.WaitGroup
	for _, p := range []priority{prioScheduled, prioOnWrite, prioOnDemand} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.acquire(ctx, p); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, p)
			mu.Unlock()
			g.release()
		}()
	}
	waitFor(t, "three waiters", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.waiting[prioScheduled]+g.waiting[prioOnWrite]+g.waiting[prioOnDemand] == 3
	})
	g.release()
	wg.Wait()
	if len(order) != 3 || order[0] != prioOnDemand || order[1] != prioOnWrite || order[2] != prioScheduled {
		t.Fatalf("order %v", order)
	}
}

// While an on-demand scan runs, on-write gets one turn per share interval.
func TestGate_OnWriteShareDuringOnDemand(t *testing.T) {
	g := newGate()
	g.share = 80 * time.Millisecond
	ctx := context.Background()
	g.setDemand(true)
	if err := g.acquire(ctx, prioOnWrite); err != nil { // first turn: at once
		t.Fatal(err)
	}
	g.release()
	start := time.Now()
	if err := g.acquire(ctx, prioOnWrite); err != nil {
		t.Fatal(err)
	}
	g.release()
	if d := time.Since(start); d < 60*time.Millisecond {
		t.Errorf("second on-write turn after %v, want ~80ms", d)
	}
	g.setDemand(false)
	start = time.Now()
	if err := g.acquire(ctx, prioOnWrite); err != nil {
		t.Fatal(err)
	}
	g.release()
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("on-write waited %v with no on-demand scan", d)
	}
}

func TestGate_Cancel(t *testing.T) {
	g := newGate()
	if err := g.acquire(context.Background(), prioOnDemand); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	why := errors.New("stopping")
	done := make(chan error, 1)
	go func() { done <- g.acquire(ctx, prioScheduled) }()
	cancel(why)
	if err := <-done; !errors.Is(err, why) {
		t.Fatalf("err %v, want the cause", err)
	}
	g.mu.Lock()
	w := g.waiting[prioScheduled]
	g.mu.Unlock()
	if w != 0 {
		t.Fatalf("%d waiters left", w)
	}
	g.release()
	if err := g.acquire(context.Background(), prioScheduled); err != nil {
		t.Fatal(err)
	}
}
