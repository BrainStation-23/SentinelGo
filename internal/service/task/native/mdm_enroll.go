package native

import (
	"context"
	"errors"
	"sync"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// MDMEnroller starts MDM enrollment as the task payload asks (method auto,
// ade or profile; contract v1, #350) and returns the outcome note
// ("<code>: <detail>"). The service installs it.
type MDMEnroller func(ctx context.Context, payload map[string]interface{}) (string, error)

var (
	mdmEnrollerMu sync.RWMutex
	mdmEnroller   MDMEnroller
)

// SetMDMEnroller installs (or with nil removes) the hook mdm-enroll calls.
func SetMDMEnroller(f MDMEnroller) {
	mdmEnrollerMu.Lock()
	defer mdmEnrollerMu.Unlock()
	mdmEnroller = f
}

// mdmEnrollHandler is the mdm-enroll native task: get the device enrolled in
// this deployment's MDM. A device enrolled in another MDM is never touched.
type mdmEnrollHandler struct{}

func init() { Register(&mdmEnrollHandler{}) }

func (h *mdmEnrollHandler) Slugs() []string { return []string{"mdm-enroll", "mdm_enroll"} }

func (h *mdmEnrollHandler) Run(ctx context.Context, _ *config.Config, task taskstore.Task) (string, error) {
	mdmEnrollerMu.RLock()
	f := mdmEnroller
	mdmEnrollerMu.RUnlock()
	if f == nil {
		return "", errors.New("mdm-enroll: unavailable: the agent's session services aren't running")
	}
	return f(ctx, task.Payload)
}

// PostRun reports the new MDM state right away instead of at the next
// inventory.
func (h *mdmEnrollHandler) PostRun() []string { return []string{"sync-inventory"} }
