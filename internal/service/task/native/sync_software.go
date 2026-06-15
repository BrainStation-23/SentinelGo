package native

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	swsvc "sentinelgo/internal/service/software"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// sendSoftwareFn is the RPC send entry point. Replaced in tests.
var sendSoftwareFn = func(ctx context.Context, svc *swsvc.SoftwareService, deviceID string, catalog []swsvc.SoftwareInfo, cfg *config.Config) error {
	return svc.SendByRPC(ctx, deviceID, catalog, cfg)
}

// getSoftwareListFn returns the installed software list plus the set of source
// categories that were authoritatively scanned. Replaced in tests.
var getSoftwareListFn = func(svc *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, map[string]bool) {
	return svc.GetSoftwareList()
}

type syncSoftwareHandler struct{}

func init() { Register(&syncSoftwareHandler{}) }

func (h *syncSoftwareHandler) Slugs() []string {
	return []string{"sync-software"}
}

func (h *syncSoftwareHandler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
	configDir := filepath.Dir(cfg.Path)
	swStore, err := store.NewSoftwareStore(filepath.Join(configDir, "software.sqlite"))
	if err != nil {
		return "", fmt.Errorf("sync-software: open software store: %w", err)
	}
	defer func() {
		if err := swStore.Close(); err != nil {
			log.Printf("sync-software: close software store: %v", err)
		}
	}()

	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(cfg.SupabaseURL)
	svc.SetEdgeFunctionConfig(cfg.SupabaseURL+"/functions/v1/sync-software", cfg.AccessToken)

	freshList, scannedSources := getSoftwareListFn(svc)

	if err := swStore.SyncBatch(freshList, time.Now(), scannedSources); err != nil {
		// Transactional: a failed SyncBatch rolled back, so the catalog is unchanged.
		// Bail rather than upload a stale catalog and clear the queue (which would mask
		// the failure). The pending-sync marker, if any, is left for the next run.
		return "", fmt.Errorf("sync-software: store sync: %w", err)
	}
	if err := swStore.QueueSync(); err != nil {
		log.Printf("sync-software: queue sync error: %v", err)
	}

	catalog, err := swStore.GetAll()
	if err != nil {
		return "", fmt.Errorf("sync-software: read catalog: %w", err)
	}
	if len(catalog) == 0 {
		_ = swStore.ClearSync()
		return "software catalog is empty, nothing to upload", nil
	}

	if err := sendSoftwareFn(ctx, svc, cfg.DeviceID, catalog, cfg); err != nil {
		return "", fmt.Errorf("sync-software: send data: %w", err)
	}

	if err := swStore.ClearSync(); err != nil {
		log.Printf("sync-software: clear sync error: %v", err)
	}

	return fmt.Sprintf("software synced successfully: %s catalog entries (%s fresh)",
		sanitize.ForLog(fmt.Sprintf("%d", len(catalog))),
		sanitize.ForLog(fmt.Sprintf("%d", len(freshList)))), nil
}
