package native

import (
	"context"
	"errors"
	"sync"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// MDMUnenroller removes this deployment's MDM enrollment (#356) and returns
// the outcome note. The service installs it.
type MDMUnenroller func(ctx context.Context, payload map[string]interface{}) (string, error)

var (
	mdmUnenrollerMu sync.RWMutex
	mdmUnenroller   MDMUnenroller
)

// SetMDMUnenroller installs (or with nil removes) the hook mdm-unenroll calls.
func SetMDMUnenroller(f MDMUnenroller) {
	mdmUnenrollerMu.Lock()
	defer mdmUnenrollerMu.Unlock()
	mdmUnenroller = f
}

// mdmUnenrollHandler is the mdm-unenroll native task: offboarding from the
// console. Another MDM's enrollment is never touched.
type mdmUnenrollHandler struct{}

func init() { Register(&mdmUnenrollHandler{}) }

func (h *mdmUnenrollHandler) Slugs() []string { return []string{"mdm-unenroll", "mdm_unenroll"} }

func (h *mdmUnenrollHandler) Run(ctx context.Context, _ *config.Config, task taskstore.Task) (string, error) {
	mdmUnenrollerMu.RLock()
	f := mdmUnenroller
	mdmUnenrollerMu.RUnlock()
	if f == nil {
		return "", errors.New("mdm-unenroll: unavailable: the agent isn't fully started")
	}
	return f(ctx, task.Payload)
}

// PostRun reports the new MDM state right away.
func (h *mdmUnenrollHandler) PostRun() []string { return []string{"sync-inventory"} }
