package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	postgrest "github.com/supabase-community/postgrest-go"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
)

// LatestRelease is the row returned by the get_latest_agent_release RPC.
type LatestRelease struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	AssetName   string    `json:"asset_name"`
	AssetPath   string    `json:"asset_path"` // e.g. "v1.4.2/sentinelgo-linux-amd64"
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
}

var updateMutex sync.Mutex

// windowsServiceName is the SCM service name registered at install time
// (see cmd/sentinelgo/main.go). The Windows update path restarts via SCM
// because a running .exe cannot be replaced in place.
const windowsServiceName = "SentinelGo"

// rpcTimeout caps the release-discovery RPC so a hung connection cannot block
// the update path indefinitely while holding updateMutex.
const releaseRPCTimeout = 30 * time.Second

// connectivityClient is a short-timeout client used only for connectivity probes.
var connectivityClient = httpx.NewClient(10 * time.Second)

// CheckAndApply checks for a newer release via Supabase RPC and applies the
// update if one is available.
//
// Order of operations is deliberate:
//  1. Compare against the COMPILED-IN running version (config.Version), not the
//     persisted cfg.CurrentVersion.
//  2. Only update on a strictly-newer semantic version (blocks downgrades).
//  3. Require a SHA256 checksum (from RPC) and an ed25519 signature (from Storage).
//  4. Download and verify BEFORE replacing anything.
//  5. Replace + restart via the OS service manager.
func CheckAndApply(ctx context.Context, cfg *config.Config) error {
	updateMutex.Lock()
	defer updateMutex.Unlock()

	latest, err := fetchLatestRelease(ctx, cfg)
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}
	if latest == nil {
		log.Println("Updater: no release configured in Supabase yet, skipping")
		return nil
	}

	running := config.Version
	newer, err := isNewerVersion(latest.Version, running)
	if err != nil {
		// Cannot compare versions (e.g. a "dev" build). Skip.
		fmt.Printf("Skipping update: cannot compare versions (%v)\n", err)
		return nil
	}
	if !newer {
		fmt.Printf("Already up to date (running %s, latest %s)\n",
			sanitize.ForLog(running), sanitize.ForLog(latest.Version))
		return nil
	}

	if latest.SHA256 == "" {
		return fmt.Errorf("refusing to update to %s: no SHA256 in release manifest",
			sanitize.ForLog(latest.Version))
	}

	fmt.Printf("Found update: %s -> %s\n", sanitize.ForLog(running), sanitize.ForLog(latest.Version))

	backupPath, err := createBackup()
	if err != nil {
		return fmt.Errorf("refusing to update without a backup: %w", err)
	}
	fmt.Printf("Created backup: %s\n", backupPath)

	// sig is stored alongside the binary with a .sig suffix, mirroring GitHub releases.
	sigAssetPath := latest.AssetPath + ".sig"

	newPath, actualChecksum, err := downloadAndVerify(ctx, cfg, latest.AssetPath, latest.SHA256, sigAssetPath, latest.Size)
	if err != nil {
		_ = removeFile(backupPath)
		return fmt.Errorf("download and verify failed: %w", err)
	}
	if actualChecksum != latest.SHA256 {
		_ = removeFile(backupPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", latest.SHA256, actualChecksum)
	}

	if runtime.GOOS != "windows" {
		if err := atomicReplace(newPath); err != nil {
			if rbErr := rollbackFromBackup(backupPath); rbErr != nil {
				return fmt.Errorf("atomic replace failed (%v) and rollback failed: %w", err, rbErr)
			}
			_ = removeFile(backupPath)
			return fmt.Errorf("atomic replace failed, rolled back to previous version: %w", err)
		}
	}

	fmt.Printf("Update verified and staged: %s -> %s\n", running, latest.Version)
	// Windows completes the swap after this process exits. Its helper retains
	// the backup until the replacement has remained RUNNING, and restores it if
	// the swap/startup check fails. Other platforms have already completed the
	// atomic replacement above.
	if runtime.GOOS != "windows" {
		_ = removeFile(backupPath)
	}

	return restart(newPath, backupPath)
}

// CheckAndApplyWithRetry performs an update check and apply with exponential
// backoff retry. Backoff starts at 5 s and caps at 5 min.
func CheckAndApplyWithRetry(ctx context.Context, cfg *config.Config) error {
	const maxAttempts = 3
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := backoffDuration(attempt - 1)
			log.Printf("Update attempt %d/%d after %s backoff", attempt+1, maxAttempts, wait)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		err := CheckAndApply(ctx, cfg)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("Update attempt %d/%d failed: %v", attempt+1, maxAttempts, err)
	}

	return fmt.Errorf("update failed after %d attempts: %w", maxAttempts, lastErr)
}

// backoffDuration returns the wait duration for retry attempt n (0-indexed).
// Doubles from 5 s, capped at 5 min.
func backoffDuration(n int) time.Duration {
	d := 5 * time.Second * (1 << uint(n))
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// fetchLatestRelease calls the get_latest_agent_release RPC and returns the
// result, or nil when no release is configured yet. The platform and arch are
// derived from runtime.GOOS / runtime.GOARCH.
func fetchLatestRelease(ctx context.Context, cfg *config.Config) (*LatestRelease, error) {
	client := postgrest.NewClient(
		cfg.SupabaseURL+"/rest/v1",
		"public",
		map[string]string{
			"Authorization": "Bearer " + cfg.GetAccessToken(),
			"apikey":        cfg.SupabaseKey,
		},
	)

	rawResult, err := rpcutil.CallWithTimeout(ctx, releaseRPCTimeout, func() (string, error) {
		return client.Rpc("get_latest_agent_release", "", map[string]interface{}{
			"p_platform": runtime.GOOS,
			"p_arch":     runtime.GOARCH,
		}), client.ClientError
	})
	if err != nil {
		return nil, fmt.Errorf("get_latest_agent_release RPC: %w", err)
	}

	var rows []LatestRelease
	if err := json.Unmarshal([]byte(rawResult), &rows); err != nil {
		return nil, fmt.Errorf("parse RPC response: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// CheckInternetConnectivity checks if the network is up by TCP-dialing the
// Supabase host first, then falling back to well-known public endpoints.
func CheckInternetConnectivity(supabaseURL string) bool {
	endpoints := []string{
		"google.com:443",
		"cloudflare.com:443",
	}

	// Prefer checking the Supabase host directly.
	if u, err := url.Parse(supabaseURL); err == nil && u.Host != "" {
		host := u.Hostname()
		endpoints = append([]string{host + ":443"}, endpoints...)
	}

	for _, endpoint := range endpoints {
		conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("Error closing connection to %s: %v", endpoint, closeErr)
			}
			log.Printf("Internet connectivity confirmed via %s", endpoint)
			return true
		}
	}

	log.Printf("No internet connectivity detected")
	return false
}

// CheckInternetWithHTTP verifies connectivity by issuing a GET to the Supabase
// REST endpoint.
func CheckInternetWithHTTP(supabaseURL string) bool {
	resp, err := connectivityClient.Get(supabaseURL + "/rest/v1/")
	if err != nil {
		log.Printf("HTTP connectivity check failed: %v", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Any HTTP response (even 401/404) means the host is reachable.
	if resp.StatusCode >= http.StatusOK {
		log.Printf("HTTP connectivity confirmed to Supabase (%d)", resp.StatusCode)
		return true
	}
	return false
}

// StartupUpdateCheck checks connectivity then attempts an update if connected.
func StartupUpdateCheck(ctx context.Context, cfg *config.Config) error {
	log.Println("Performing startup update check...")

	if !CheckInternetConnectivity(cfg.SupabaseURL) {
		log.Println("No internet connection on startup, skipping update check")
		return nil
	}

	if !CheckInternetWithHTTP(cfg.SupabaseURL) {
		log.Println("HTTP connectivity check failed on startup, skipping update check")
		return nil
	}

	log.Println("Internet connection confirmed, checking for updates...")

	if err := CheckAndApplyWithRetry(ctx, cfg); err != nil {
		log.Printf("Startup update check failed: %v", err)
		return fmt.Errorf("startup update check failed: %w", err)
	}

	log.Println("Startup update check completed successfully")
	return nil
}

// AutoUpdateChecker runs automatic update checks in the background every hour.
func AutoUpdateChecker(ctx context.Context, cfg *config.Config) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Jitter: spread checks across up to 5 minutes.
			jitter := time.Duration(rand.Intn(5*60)) * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(jitter):
			}

			log.Println("Checking for updates...")
			if err := CheckAndApplyWithRetry(ctx, cfg); err != nil {
				log.Printf("Auto-update failed: %v\n", err)
			} else {
				log.Println("Auto-update completed successfully")
			}
		}
	}
}
