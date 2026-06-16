package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"

	postgrest "github.com/supabase-community/postgrest-go"
)

const rpcTimeout = 60 * time.Second

// SendByRPC sends the full services snapshot to the agent_upsert_services RPC.
func (s *ServicesService) SendByRPC(ctx context.Context, _ string, svcs []models.ServiceInfo, cfg *config.Config) error {
	if s.supabaseURL == "" {
		return fmt.Errorf("supabase base URL not configured for RPC call")
	}
	if s.apiKey == "" {
		return fmt.Errorf("access token not configured for RPC call")
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

	client := postgrest.NewClient(
		s.supabaseURL+"/rest/v1",
		"public",
		map[string]string{
			"Authorization": "Bearer " + accessToken,
			"apikey":        anonKey,
		},
	)

	rawResult, err := rpcutil.CallWithTimeout(ctx, rpcTimeout, func() (string, error) {
		return client.Rpc("agent_upsert_services", "", map[string]interface{}{
			"payload": map[string]interface{}{
				"snapshot": "full",
				"services": items,
			},
		}), client.ClientError
	})
	if err != nil {
		return fmt.Errorf("call agent_upsert_services RPC: %w", err)
	}
	if rawResult == "" {
		return fmt.Errorf("call agent_upsert_services RPC: empty response")
	}

	if len(strings.TrimSpace(rawResult)) > 0 {
		var result map[string]interface{}
		if json.Unmarshal([]byte(rawResult), &result) == nil {
			if msg, ok := result["message"]; ok {
				return fmt.Errorf("agent_upsert_services error: %v", msg)
			}
		}
	}

	sanitizedCount := sanitize.ForLog(fmt.Sprintf("%d", len(items)))
	fmt.Printf("RPC agent_upsert_services completed: %s service items\n", sanitizedCount)
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
