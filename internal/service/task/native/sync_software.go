package native

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	swsvc "sentinelgo/internal/service/software"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// getSoftwareListFn returns the installed software list and whether the scan was
// complete. Replaced in tests.
var getSoftwareListFn = func(svc *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, bool) {
	return svc.GetSoftwareListWithStatus()
}

// syncSoftwareFn persists the scan to the local catalog and sends it to the
// backend, returning skipped=true when the upload was deduped. Replaced in tests.
var syncSoftwareFn = func(ctx context.Context, svc *swsvc.SoftwareService, cfg *config.Config, list []swsvc.SoftwareInfo, complete bool) (bool, error) {
	// Persist to the same local catalog the scheduler uses (best-effort; sending
	// is the primary goal). A short-lived handle is fine: force sync is rare.
	var cat swsvc.Catalog
	dbPath := filepath.Join(filepath.Dir(cfg.Path), store.SoftwareDBName)
	if st, err := store.NewSoftwareStore(dbPath); err != nil {
		log.Printf("sync-software: open catalog (continuing without persistence): %v", err)
	} else {
		cat = st
		defer func() { _ = st.Close() }()
	}
	return svc.SyncCatalog(ctx, cat, cfg.DeviceID, list, complete, cfg)
}

type syncSoftwareHandler struct{}

func init() { Register(&syncSoftwareHandler{}) }

func (h *syncSoftwareHandler) Slugs() []string {
	return []string{"sync-software"}
}

func (h *syncSoftwareHandler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(cfg.SupabaseURL)

	list, complete := getSoftwareListFn(svc)
	if len(list) == 0 {
		log.Printf("sync-software: no software found; skipping upload")
		return "software list is empty, nothing to upload", nil
	}

	skipped, err := syncSoftwareFn(ctx, svc, cfg, list, complete)
	if err != nil {
		return "", fmt.Errorf("sync-software: send data: %w", err)
	}

	count := sanitize.ForLog(fmt.Sprintf("%d", len(list)))
	if skipped {
		return fmt.Sprintf("software unchanged since last sync (%s items already up to date)", count), nil
	}
	return fmt.Sprintf("software synced successfully: %s items", count), nil
}
