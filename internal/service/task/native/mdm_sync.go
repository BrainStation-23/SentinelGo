package native

import (
	"context"
	"errors"
	"sync"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// MDMSyncer starts an MDM session for this deployment's enrollment (#357)
// and returns the outcome note. The service installs it.
type MDMSyncer func(ctx context.Context, payload map[string]interface{}) (string, error)

var (
	mdmSyncerMu sync.RWMutex
	mdmSyncer   MDMSyncer
)

// SetMDMSyncer installs (or with nil removes) the hook mdm-sync calls.
func SetMDMSyncer(f MDMSyncer) {
	mdmSyncerMu.Lock()
	defer mdmSyncerMu.Unlock()
	mdmSyncer = f
}

// mdmSyncHandler is the mdm-sync native task: the backend queues it when it
// queues an MDM command, so the device fetches the command now instead of
// at its next poll.
type mdmSyncHandler struct{}

func init() { Register(&mdmSyncHandler{}) }

func (h *mdmSyncHandler) Slugs() []string { return []string{"mdm-sync", "mdm_sync"} }

func (h *mdmSyncHandler) Run(ctx context.Context, _ *config.Config, task taskstore.Task) (string, error) {
	mdmSyncerMu.RLock()
	f := mdmSyncer
	mdmSyncerMu.RUnlock()
	if f == nil {
		return "", errors.New("mdm-sync: unavailable: the agent isn't fully started")
	}
	return f(ctx, task.Payload)
}
