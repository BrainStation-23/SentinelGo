package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

	err = rpcutil.WithEnqueueRetry(ctx, func(ctx context.Context) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("apikey", anonKey)

		resp, err := s.client.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		var enqResp rpcutil.EnqueueResponse
		if err := json.Unmarshal(respBody, &enqResp); err != nil {
			log.Printf("[services] enqueue accepted but response parse failed: %v", err)
		} else {
			log.Printf("[services] enqueued: msg_id=%d queue=%s", enqResp.MsgID, enqResp.Queue)
		}
		return resp.StatusCode, nil
	})
	if err != nil {
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
