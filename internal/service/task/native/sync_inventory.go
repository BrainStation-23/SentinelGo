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
var collectSysInfoFn = func(agentVersion string) *shared.SystemInfo { return osinfo.Collect(agentVersion) }
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

	type collectResult struct{ info *shared.SystemInfo }
	ch := make(chan collectResult, 1)
	go func() { ch <- collectResult{collectSysInfoFn(cfg.CurrentVersion)} }()

	var sysInfo *shared.SystemInfo
	select {
	case <-tctx.Done():
		return "", fmt.Errorf("sync-inventory: osinfo.Collect timed out after %v", syncInventoryTimeout)
	case r := <-ch:
		sysInfo = r.info
	}

	if sysInfo == nil {
		return "", fmt.Errorf("sync-inventory: system info collection returned no data")
	}

	if err := updateAgentInfoFn(tctx, cfg, sysInfo); err != nil {
		return "", fmt.Errorf("sync-inventory: %w", err)
	}
	return "inventory synced successfully", nil
}
