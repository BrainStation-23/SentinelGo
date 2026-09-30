package software

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	body = sanitize.StripJSONNUL(body)

	url := s.supabaseURL + "/rest/v1/rpc/agent_enqueue_software"
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	if err := rpcutil.PostEnqueue(ctx, s.client, url, accessToken, anonKey, body, "software"); err != nil {
		return fmt.Errorf("agent_enqueue_software: %w", err)
	}

	log.Printf("agent_enqueue_software completed: %s items", sanitize.ForLog(fmt.Sprintf("%d", len(items))))
	return nil
}
