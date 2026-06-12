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

	freshList := svc.GetSoftwareList()

	if err := swStore.SyncBatch(freshList, time.Now()); err != nil {
		log.Printf("sync-software: store sync error: %v", err)
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

	if err := svc.SendByRPC(ctx, cfg.DeviceID, catalog, cfg); err != nil {
		return "", fmt.Errorf("sync-software: send data: %w", err)
	}

	if err := swStore.ClearSync(); err != nil {
		log.Printf("sync-software: clear sync error: %v", err)
	}

	return fmt.Sprintf("software synced successfully: %s catalog entries (%s fresh)",
		sanitize.ForLog(fmt.Sprintf("%d", len(catalog))),
		sanitize.ForLog(fmt.Sprintf("%d", len(freshList)))), nil
}
