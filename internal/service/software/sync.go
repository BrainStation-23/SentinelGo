package software

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/supabase"
)

const rpcTimeout = 60 * time.Second

// maxMetadataLen caps the optional metadata strings. They come from package
// metadata the agent does not control (a package names its own maintainer or
// vendor), and no real value comes close to this length.
const maxMetadataLen = 256

// truncateRunes shortens s to at most n runes without splitting a character.
// The result is always a prefix of s (an invalid byte counts as one rune).
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// SendByRPC sends the full software list to the agent_enqueue_software RPC.
func (s *SoftwareService) SendByRPC(ctx context.Context, _ string, software []SoftwareInfo, cfg *config.Config) error {
	if s.supabaseURL == "" {
		return fmt.Errorf("supabase base URL not configured for RPC call")
	}

	c := enqueueClient(s.supabaseURL, cfg, s.client)

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
		Publisher        string `json:"publisher,omitempty"`
		InstallDate      string `json:"install_date,omitempty"`
		SizeBytes        int64  `json:"size_bytes,omitempty"`
		Architecture     string `json:"architecture,omitempty"`
		BundleID         string `json:"bundle_id,omitempty"`
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
			Publisher:        truncateRunes(sw.Publisher, maxMetadataLen),
			InstallDate:      truncateRunes(sw.InstallDate, maxMetadataLen),
			SizeBytes:        sw.SizeBytes,
			Architecture:     truncateRunes(sw.Architecture, maxMetadataLen),
			BundleID:         truncateRunes(sw.BundleID, maxMetadataLen),
		})
	}

	// The client strips NUL escapes Postgres would reject from the body.
	params := map[string]interface{}{
		"payload": map[string]interface{}{
			"software": items,
		},
	}

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	if err := rpcutil.PostEnqueue(ctx, c, "agent_enqueue_software", params, "software"); err != nil {
		return fmt.Errorf("agent_enqueue_software: %w", err)
	}

	log.Printf("agent_enqueue_software completed: %s items", sanitize.ForLog(fmt.Sprintf("%d", len(items))))
	return nil
}

// enqueueClient returns a Supabase client for baseURL that reads the access
// token from cfg on every request (cfg may be nil, e.g. in tests, in which case
// no bearer is sent).
func enqueueClient(baseURL string, cfg *config.Config, hc *http.Client) *supabase.Client {
	var anonKey string
	token := func() string { return "" }
	if cfg != nil {
		anonKey = cfg.SupabaseKey
		token = cfg.GetAccessToken
	}
	return supabase.New(baseURL, anonKey, token, supabase.WithHTTPClient(hc))
}
