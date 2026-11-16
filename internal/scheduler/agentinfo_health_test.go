package scheduler

import (
	"errors"
	"fmt"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/rpcutil"
)

// Only an upload the server accepted confirms a self-update healthy (#503):
// a rejected (dropped) payload is not retried but proves nothing.
func TestAfterAgentInfoSend_ConfirmsOnlyAcceptedUploads(t *testing.T) {
	calls := 0
	prev := confirmHealthyFn
	confirmHealthyFn = func(*config.Config) { calls++ }
	t.Cleanup(func() { confirmHealthyFn = prev })
	cfg := &config.Config{}

	if err := afterAgentInfoSend(cfg, nil); err != nil || calls != 1 {
		t.Fatalf("accepted: err %v, confirms %d; want nil and 1", err, calls)
	}
	dropped := fmt.Errorf("%w (HTTP 400): bad payload", rpcutil.ErrPayloadDropped)
	if err := afterAgentInfoSend(cfg, dropped); err != nil || calls != 1 {
		t.Fatalf("rejected: err %v, confirms %d; want nil and still 1", err, calls)
	}
	other := errors.New("network down")
	if err := afterAgentInfoSend(cfg, other); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("failed: err %v, confirms %d; want the error and still 1", err, calls)
	}
}
