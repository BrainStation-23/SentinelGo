package software

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/store"

	postgrest "github.com/supabase-community/postgrest-go"
)

// rpcTimeout bounds a single Supabase RPC so a hung connection cannot wedge the
// scheduled software-sync task.
const rpcTimeout = 60 * time.Second

// SendSoftwareData sends software data to the Edge Function, falling back to
// the PostgREST RPC if the edge function is not deployed (404).
func (s *SoftwareService) SendSoftwareData(ctx context.Context, agentID string, software []SoftwareInfo) error {
	payload := map[string]any{
		"p_agent_id":      agentID,
		"p_software_list": software,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal software data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.edgeURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("apikey", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Println("Edge function not found (404), falling back to Supabase REST API...")
		return s.sendByRestAPI(ctx, agentID, software, nil)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("edge function error: status %d, body: %s", resp.StatusCode, string(body))
	}

	var response struct {
		Success   bool `json:"success"`
		Processed int  `json:"processed"`
		Results   []struct {
			Name    string `json:"name"`
			Source  string `json:"source"`
			Success bool   `json:"success"`
			Error   string `json:"error,omitempty"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Printf("Edge function response: Success=%v, Processed=%d\n", response.Success, response.Processed)
	for _, result := range response.Results {
		if !result.Success {
			fmt.Printf("Failed item: %s (%s) - Error: %s\n", result.Name, result.Source, result.Error)
		}
	}

	if !response.Success {
		return fmt.Errorf("edge function returned failure")
	}

	for _, result := range response.Results {
		if !result.Success {
			return fmt.Errorf("software %s failed: %s", result.Name, result.Error)
		}
	}

	return nil
}

// SendByRPC is the exported entry point for sendByRestAPI.
func (s *SoftwareService) SendByRPC(ctx context.Context, agentID string, software []SoftwareInfo, cfg *config.Config) error {
	return s.sendByRestAPI(ctx, agentID, software, cfg)
}

// sendByRestAPI sends the full software list in one RPC call to agent_upsert_software.
func (s *SoftwareService) sendByRestAPI(ctx context.Context, _ string, software []SoftwareInfo, cfg *config.Config) error {
	if s.supabaseURL == "" {
		return fmt.Errorf("supabase base URL not configured for RPC call")
	}
	if s.apiKey == "" {
		return fmt.Errorf("access token not configured for RPC call")
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
		Status           string `json:"status,omitempty"`
		IsActive         bool   `json:"is_active"`
		FirstSeenAt      string `json:"first_seen_at,omitempty"`
		LastSeenAt       string `json:"last_seen_at,omitempty"`
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
			Status:           sw.Status,
			IsActive:         sw.IsActive,
			FirstSeenAt:      sw.FirstSeenAt,
			LastSeenAt:       sw.LastSeenAt,
		})
	}

	var accessToken string
	var anonKey string
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
		return client.Rpc("agent_upsert_software", "", map[string]interface{}{
			"payload": map[string]interface{}{
				"software": items,
			},
		}), client.ClientError
	})
	if err != nil {
		return fmt.Errorf("call agent_upsert_software RPC: %w", err)
	}
	if rawResult == "" {
		return fmt.Errorf("call agent_upsert_software RPC: empty response")
	}

	if len(strings.TrimSpace(rawResult)) > 0 {
		var result map[string]interface{}
		if json.Unmarshal([]byte(rawResult), &result) == nil {
			if msg, ok := result["message"]; ok {
				return fmt.Errorf("agent_upsert_software error: %v", msg)
			}
		}
	}

	fmt.Printf("RPC agent_upsert_software completed: %d software items\n", len(items))
	return nil
}

// StartSoftwareSync runs the standalone software sync loop.
func (s *SoftwareService) StartSoftwareSync(ctx context.Context, cfg *config.Config, softwareProvider func() []SoftwareInfo) error {
	storePath := filepath.Join(filepath.Dir(cfg.Path), "software.sqlite")
	swStore, err := store.NewSoftwareStore(storePath)
	if err != nil {
		return fmt.Errorf("open software store: %w", err)
	}
	defer func() {
		if err := swStore.Close(); err != nil {
			fmt.Printf("Failed to close software store: %v\n", err)
		}
	}()

	interval := cfg.GetSoftwareInfoUpdateInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Software sync service stopped")
			return nil

		case <-ticker.C:
			syncTime := time.Now()
			freshList := softwareProvider()

			if err := swStore.SyncBatch(freshList, syncTime); err != nil {
				fmt.Printf("Software store sync error: %v\n", err)
			} else {
				_ = swStore.QueueSync()
			}

			pending, err := swStore.HasPendingSync()
			if err != nil || !pending {
				continue
			}

			catalog, err := swStore.GetAll()
			if err != nil {
				fmt.Printf("Failed to read software catalog: %v\n", err)
				continue
			}
			if len(catalog) == 0 {
				continue
			}

			if err := s.SendByRPC(ctx, cfg.DeviceID, catalog, cfg); err != nil {
				fmt.Printf("Failed to send software data: %v\n", err)
				continue
			}

			_ = swStore.ClearSync()

			sanitizedInterval := sanitize.ForLog(fmt.Sprintf("%v", interval))
			fmt.Printf("Software sync completed: %d catalog entries (%d fresh), interval: %s\n",
				len(catalog), len(freshList), sanitizedInterval)
		}
	}
}
