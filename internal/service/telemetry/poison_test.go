package telemetry

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
)

// TestPoisonedMessagesDoNotBlockHealthyOnes is the head-of-line blocking check.
//
// Poisoned rows sit at the head of the queue because GetPending orders by
// (priority, id) and they are the oldest. If a full page of them is fetched,
// nothing behind them can ever be delivered — one permanently rejected batch
// would stall telemetry for the device indefinitely.
func TestPoisonedMessagesDoNotBlockHealthyOnes(t *testing.T) {
	var rejectAll atomic.Bool
	var delivered atomic.Int32

	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		if rejectAll.Load() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	seedSectionState(t, svc, "identity")

	// Fill more than one page with messages the backend refuses.
	rejectAll.Store(true)
	poisonCount := drainBatchSize + 5
	for i := 0; i < poisonCount; i++ {
		enqueueTestMessage(t, svc, "identity", `{"payload":{"bad":true}}`)
	}

	// Burn through their attempt budget.
	for i := 0; i < maxDeliveryAttempts; i++ {
		if _, err := svc.Flush(context.Background()); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}

	// Now the backend recovers and a healthy message is queued behind them.
	rejectAll.Store(false)
	enqueueTestMessage(t, svc, "identity", `{"payload":{"good":true}}`)

	if _, err := svc.Flush(context.Background()); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}

	if delivered.Load() == 0 {
		t.Fatalf("head-of-line blocking: %d poisoned message(s) prevented a healthy "+
			"message behind them from being delivered", poisonCount)
	}
}
