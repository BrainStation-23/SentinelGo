package native

import (
	"context"
	"fmt"
	"log"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	swsvc "sentinelgo/internal/service/software"
	"sentinelgo/internal/taskstore"
)

// sendSoftwareFn is the RPC send entry point. Replaced in tests.
var sendSoftwareFn = func(ctx context.Context, svc *swsvc.SoftwareService, deviceID string, list []swsvc.SoftwareInfo, cfg *config.Config) error {
	_, err := svc.SendByRPCIfChanged(ctx, deviceID, list, cfg)
	return err
}

// getSoftwareListFn returns the installed software list. Replaced in tests.
var getSoftwareListFn = func(svc *swsvc.SoftwareService) []swsvc.SoftwareInfo {
	return svc.GetSoftwareList()
}

type syncSoftwareHandler struct{}

func init() { Register(&syncSoftwareHandler{}) }

func (h *syncSoftwareHandler) Slugs() []string {
	return []string{"sync-software"}
}

func (h *syncSoftwareHandler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(cfg.SupabaseURL)

	freshList := getSoftwareListFn(svc)
	if len(freshList) == 0 {
		log.Printf("sync-software: no software found; skipping upload")
		return "software list is empty, nothing to upload", nil
	}

	if err := sendSoftwareFn(ctx, svc, cfg.DeviceID, freshList, cfg); err != nil {
		return "", fmt.Errorf("sync-software: send data: %w", err)
	}

	return fmt.Sprintf("software synced successfully: %s items",
		sanitize.ForLog(fmt.Sprintf("%d", len(freshList)))), nil
}
