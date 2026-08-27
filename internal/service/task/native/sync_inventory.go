package native

import (
	"context"
	"fmt"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo"
	"sentinelgo/internal/osinfo/shared"
	agentsvc "sentinelgo/internal/service/agent"
	"sentinelgo/internal/taskstore"
)

const syncInventoryTimeout = 90 * time.Second

// collectSysInfoFn and updateAgentInfoFn are the real production implementations;
// replaced in tests to avoid network calls and OS-level collection.
var collectSysInfoFn = func(ctx context.Context) (*shared.SystemInfo, error) {
	return osinfo.CollectContext(ctx)
}
var updateAgentInfoFn = func(ctx context.Context, cfg *config.Config, info *shared.SystemInfo) error {
	return agentsvc.NewAgentService().UpdateAgentInfo(ctx, cfg, info)
}

type syncInventoryHandler struct{}

func init() { Register(&syncInventoryHandler{}) }

func (h *syncInventoryHandler) Slugs() []string {
	return []string{"sync-inventory"}
}

func (h *syncInventoryHandler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, syncInventoryTimeout)
	defer cancel()

	// Called directly rather than in a goroutine the timeout abandons; see the
	// same change in scheduler.handleAgentInfoUpdate.
	sysInfo, err := collectSysInfoFn(tctx)
	if err != nil {
		return "", fmt.Errorf("sync-inventory: collection cancelled after %v: %w", syncInventoryTimeout, err)
	}

	if sysInfo == nil {
		return "", fmt.Errorf("sync-inventory: system info collection returned no data")
	}

	if err := updateAgentInfoFn(tctx, cfg, sysInfo); err != nil {
		return "", fmt.Errorf("sync-inventory: %w", err)
	}
	return "inventory synced successfully", nil
}
