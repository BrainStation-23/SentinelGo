package software

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
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
)

const rpcTimeout = 60 * time.Second

// SendByRPC sends the full software list to the agent_enqueue_software RPC.
func (s *SoftwareService) SendByRPC(ctx context.Context, _ string, software []SoftwareInfo, cfg *config.Config) error {
	if s.supabaseURL == "" {
		return fmt.Errorf("supabase base URL not configured for RPC call")
	}

	var accessToken, anonKey string
	if cfg != nil {
		accessToken = cfg.GetAccessToken()
		anonKey = cfg.SupabaseKey
	}

	type softwareItem struct {
		Name             string `json:"name"`
		Source           string `json:"source"`
		Type             string `json:"type"`
		InstalledVersion string `json:"installed_version,omitempty"`
		DisplayName      string `json:"display_name,omitempty"`
		SoftwarePackage  string `json:"software_package,omitempty"`
		AppStoreApp      string `json:"app_store_app,omitempty"`
		LastOpened       string `json:"last_opened,omitempty"`
		FilePath         string `json:"file_path,omitempty"`
		FirstSeenAt      string `json:"first_seen_at,omitempty"`
	}

	items := make([]softwareItem, 0, len(software))
	for _, sw := range software {
		items = append(items, softwareItem{
			Name:             sw.Name,
			Source:           sw.Source,
			Type:             sw.Type,
			InstalledVersion: sw.InstalledVersion,
			DisplayName:      sw.DisplayName,
			SoftwarePackage:  sw.SoftwarePackage,
			AppStoreApp:      sw.AppStoreApp,
			LastOpened:       sw.LastOpened,
			FilePath:         sw.FilePath,
			FirstSeenAt:      sw.FirstSeenAt,
		})
	}

	body, err := json.Marshal(map[string]interface{}{
		"payload": map[string]interface{}{
			"software": items,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal software payload: %w", err)
	}

	url := s.supabaseURL + "/rest/v1/rpc/agent_enqueue_software"
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
			log.Printf("[software] enqueue accepted but response parse failed: %v", err)
		} else {
			log.Printf("[software] enqueued: msg_id=%d queue=%s", enqResp.MsgID, enqResp.Queue)
		}
		return resp.StatusCode, nil
	})
	if err != nil {
		return fmt.Errorf("agent_enqueue_software: %w", err)
	}

	log.Printf("agent_enqueue_software completed: %s items", sanitize.ForLog(fmt.Sprintf("%d", len(items))))
	return nil
}
