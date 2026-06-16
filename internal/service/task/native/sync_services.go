package native

import (
	"context"
	"fmt"
	"log"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
	servicessvc "sentinelgo/internal/service/services"
	"sentinelgo/internal/taskstore"
)

// sendServicesFn is the RPC send entry point. Replaced in tests.
var sendServicesFn = func(ctx context.Context, svc *servicessvc.ServicesService, deviceID string, list []models.ServiceInfo, cfg *config.Config) error {
	return svc.SendByRPC(ctx, deviceID, list, cfg)
}

// getServicesListFn returns the running services list. Replaced in tests.
var getServicesListFn = func(svc *servicessvc.ServicesService) []models.ServiceInfo {
	return svc.GetServiceList()
}

type syncServicesHandler struct{}

func init() { Register(&syncServicesHandler{}) }

func (h *syncServicesHandler) Slugs() []string {
	return []string{"sync-services"}
}

func (h *syncServicesHandler) Run(ctx context.Context, cfg *config.Config, _ taskstore.Task) (string, error) {
	svc := servicessvc.NewServicesService()
	svc.SetSupabaseURL(cfg.SupabaseURL)
	svc.SetAPIKey(cfg.GetAccessToken())

	list := getServicesListFn(svc)
	if len(list) == 0 {
		log.Printf("sync-services: no services found; skipping upload")
		return "services list is empty, nothing to upload", nil
	}

	if err := sendServicesFn(ctx, svc, cfg.DeviceID, list, cfg); err != nil {
		return "", fmt.Errorf("sync-services: send data: %w", err)
	}

	return fmt.Sprintf("services synced successfully: %s items",
		sanitize.ForLog(fmt.Sprintf("%d", len(list)))), nil
}
