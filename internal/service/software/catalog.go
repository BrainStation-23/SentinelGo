package software

import (
	"context"
	"fmt"
	"log"

	"sentinelgo/internal/config"
)

// Catalog is the local software persistence used by a sync. *store.SoftwareStore
// satisfies it; the interface lives here so this package does not import store
// (which would create an import cycle).
type Catalog interface {
	Upsert(agentID string, items []SoftwareInfo) error
	DeleteNotIn(agentID string, activeKeys []string) error
}

// SyncCatalog persists a scan to the local catalog, then sends it to the backend
// if it changed. The whole scan is upserted (so first_seen_at accrues and the
// catalog survives restarts), but stale entries are pruned only when complete is
// true — a partial scan (e.g. a failed Windows registry query) must never be
// used to delete software that is still installed. cat may be nil to send
// without persisting. Returns skipped=true when the upload was deduped.
func (s *SoftwareService) SyncCatalog(ctx context.Context, cat Catalog, deviceID string, list []SoftwareInfo, complete bool, cfg *config.Config) (skipped bool, err error) {
	if cat != nil {
		if err := cat.Upsert(deviceID, list); err != nil {
			return false, fmt.Errorf("software catalog upsert: %w", err)
		}
		if complete {
			keys := make([]string, len(list))
			for i, sw := range list {
				keys[i] = sw.Name + "\x00" + sw.Source
			}
			if err := cat.DeleteNotIn(deviceID, keys); err != nil {
				log.Printf("[software] prune stale entries: %v", err)
			}
		} else {
			log.Printf("[software] partial scan; skipping prune to preserve catalog")
		}
	}
	return s.SendSnapshotByRPCIfChanged(ctx, deviceID, list, complete, cfg)
}
