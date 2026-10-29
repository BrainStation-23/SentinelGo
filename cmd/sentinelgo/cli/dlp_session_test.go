package cli

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/dlp/session"
)

// A second helper waits as a standby, takes over when the first releases
// the lock, and gives up when stopped.
func TestWaitForHelperLock(t *testing.T) {
	prev := helperLockRetry
	helperLockRetry = 20 * time.Millisecond
	t.Cleanup(func() { helperLockRetry = prev })

	first, ok, err := session.AcquireHelperLock()
	if err != nil || !ok {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	got := make(chan func(), 1)
	go func() {
		r, _ := waitForHelperLock(context.Background())
		got <- r
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-got:
		t.Fatal("standby took the lock while it was held")
	default:
	}
	first()
	select {
	case r := <-got:
		if r == nil {
			t.Fatal("standby got no lock")
		}
		r()
	case <-time.After(5 * time.Second):
		t.Fatal("standby didn't take over")
	}

	held, _, _ := session.AcquireHelperLock()
	defer held()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if r, err := waitForHelperLock(ctx); r != nil || err != nil {
		t.Errorf("stopped standby: release=%v err=%v", r != nil, err)
	}
}
