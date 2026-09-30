package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
)

const rpcTimeout = 60 * time.Second

// SendByRPC sends the full services snapshot to the agent_enqueue_services RPC.
func (s *ServicesService) SendByRPC(ctx context.Context, _ string, svcs []models.ServiceInfo, cfg *config.Config) error {
	if s.supabaseURL == "" {
		return fmt.Errorf("supabase base URL not configured for RPC call")
	}

	var accessToken, anonKey string
	if cfg != nil {
		accessToken = cfg.GetAccessToken()
		anonKey = cfg.SupabaseKey
	}
	if accessToken == "" {
		accessToken = s.apiKey
	}
	if anonKey == "" {
		anonKey = s.apiKey
	}

	type servicesItem struct {
		Name        string `json:"name"`
		Source      string `json:"source"`
		DisplayName string `json:"display_name,omitempty"`
		Status      string `json:"status,omitempty"`
		StartMode   string `json:"start_mode,omitempty"`
		PID         int    `json:"pid,omitempty"`
		User        string `json:"user,omitempty"`
		Description string `json:"description,omitempty"`
	}

	items := make([]servicesItem, 0, len(svcs))
	for _, svc := range svcs {
		items = append(items, servicesItem{
			Name:        svc.Name,
			Source:      normalizeServicesSource(svc.Source),
			DisplayName: svc.DisplayName,
			Status:      normalizeServicesStatus(svc.Status),
			StartMode:   normalizeServicesStartMode(svc.StartType),
			PID:         svc.PID,
			User:        svc.RunAs,
			Description: svc.Description,
		})
	}

	body, err := json.Marshal(map[string]interface{}{
		"payload": map[string]interface{}{
			"snapshot": "full",
			"services": items,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal services payload: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	body = sanitize.StripJSONNUL(body)

	url := s.supabaseURL + "/rest/v1/rpc/agent_enqueue_services"
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	if err := rpcutil.PostEnqueue(ctx, s.client, url, accessToken, anonKey, body, "services"); err != nil {
		return fmt.Errorf("agent_enqueue_services: %w", err)
	}

	log.Printf("agent_enqueue_services completed: %s items", sanitize.ForLog(fmt.Sprintf("%d", len(items))))
	return nil
}

func normalizeServicesStatus(s string) string {
	switch s {
	case "running":
		return "running"
	case "stopped":
		return "stopped"
	case "paused":
		return "paused"
	case "starting", "activating":
		return "start_pending"
	case "stopping", "deactivating":
		return "stop_pending"
	case "active":
		return "running"
	case "inactive":
		return "stopped"
	case "failed":
		return "failed"
	default:
		return "unknown"
	}
}

func normalizeServicesStartMode(s string) string {
	switch s {
	case "automatic":
		return "auto"
	case "auto_delayed":
		return "auto_delayed"
	case "manual":
		return "manual"
	case "disabled", "masked", "masked-runtime":
		return "disabled"
	case "boot":
		return "boot"
	case "system":
		return "system"
	case "static", "indirect":
		return "static"
	default:
		return ""
	}
}

func normalizeServicesSource(s string) string {
	if s == "windows_services" {
		return "windows_service"
	}
	return s
}
