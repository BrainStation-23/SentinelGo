package native

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// DLPPolicySync polls for the DLP policy now and returns the version the
// device has applied and the DLP state. The service registers it when DLP is
// enabled; it is nil otherwise.
type DLPPolicySync func(ctx context.Context) (version, state string, err error)

var (
	dlpSyncMu sync.RWMutex
	dlpSync   DLPPolicySync
)

// SetDLPPolicySync installs (or with nil removes) the hook dlp_sync_policy
// calls.
func SetDLPPolicySync(f DLPPolicySync) {
	dlpSyncMu.Lock()
	defer dlpSyncMu.Unlock()
	dlpSync = f
}

// errDLPOff is the result when DLP isn't running on the device.
var errDLPOff = errors.New("DLP is not enabled on this device (dlp_enabled is false in config.json)")

// dlpSyncPolicyHandler is "push policy now": an admin changed a DLP policy
// and wants it applied without waiting for the next poll.
type dlpSyncPolicyHandler struct{}

func init() { Register(&dlpSyncPolicyHandler{}) }

func (h *dlpSyncPolicyHandler) Slugs() []string {
	return []string{"dlp_sync_policy"}
}

func (h *dlpSyncPolicyHandler) Run(ctx context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	dlpSyncMu.RLock()
	f := dlpSync
	dlpSyncMu.RUnlock()
	if f == nil {
		return "", errDLPOff
	}
	version, state, err := f(ctx)
	if err != nil {
		return "", fmt.Errorf("dlp_sync_policy: %w", err)
	}
	if version == "" {
		return fmt.Sprintf("DLP policy synced: no policy for this device (state %s)", state), nil
	}
	return fmt.Sprintf("DLP policy synced: applied version %s (state %s)", version, state), nil
}
